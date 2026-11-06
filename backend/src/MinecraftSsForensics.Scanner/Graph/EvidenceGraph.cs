using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Graph;

/// <summary>
/// In-memory Directed Attributed Evidence Graph G = (V, E).
/// Supports causal tracking, multi-modal correlation, anti-double-counting, bounded traversal queries (k <= 4),
/// and deterministic canonical serialization.
/// </summary>
public class EvidenceGraph
{
    public const int DefaultMaxTraversalDepth = 4;
    public const int MaxGraphNodes = 50000;
    public const int MaxGraphEdges = 100000;
    public const int MaxPathSearchIterations = 10000;

    private readonly ConcurrentDictionary<string, GraphEntity> _nodes = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<GraphEdge> _edges = new();
    private readonly object _edgeLock = new();

    private readonly ConcurrentDictionary<string, List<GraphEdge>> _outgoing = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, List<GraphEdge>> _incoming = new(StringComparer.OrdinalIgnoreCase);

    public bool IsCaptured { get; set; } = true;
    public bool IsResourceBounded { get; set; } = false;
    public bool IsValid { get; set; } = true;
    public List<string> ValidationErrors { get; set; } = new();

    public int NodeCount => _nodes.Count;
    public int EdgeCount
    {
        get
        {
            lock (_edgeLock) return _edges.Count;
        }
    }

    /// <summary>
    /// Deterministically sorted nodes for repeatable canonical serialization and integrity hashes.
    /// </summary>
    [JsonPropertyName("nodes")]
    public IEnumerable<GraphEntity> Nodes => _nodes.Values.OrderBy(n => n.EntityId, StringComparer.Ordinal);

    /// <summary>
    /// Deterministically sorted edges for repeatable canonical serialization and integrity hashes.
    /// </summary>
    [JsonPropertyName("edges")]
    public IEnumerable<GraphEdge> Edges
    {
        get
        {
            lock (_edgeLock)
            {
                return _edges
                    .OrderBy(e => e.SourceEntityId, StringComparer.Ordinal)
                    .ThenBy(e => e.TargetEntityId, StringComparer.Ordinal)
                    .ThenBy(e => e.Type)
                    .ThenBy(e => e.EdgeId, StringComparer.Ordinal)
                    .ToList();
            }
        }
    }

    public EvidenceGraph()
    {
    }

    [JsonConstructor]
    public EvidenceGraph(
        IEnumerable<GraphEntity>? nodes = null,
        IEnumerable<GraphEdge>? edges = null,
        bool isCaptured = true,
        bool isResourceBounded = false,
        bool isValid = true,
        List<string>? validationErrors = null)
    {
        IsCaptured = isCaptured;
        IsResourceBounded = isResourceBounded;
        IsValid = isValid;
        if (validationErrors != null)
        {
            ValidationErrors.AddRange(validationErrors);
        }

        if (nodes != null)
        {
            foreach (var node in nodes)
            {
                AddNode(node);
            }
        }

        if (edges != null)
        {
            foreach (var edge in edges)
            {
                if (!AddEdge(edge))
                {
                    IsValid = false;
                    ValidationErrors.Add($"Invalid edge during deserialization: {edge.EdgeId} ({edge.SourceEntityId} -> {edge.TargetEntityId}) missing vertex endpoint or exceeds bounds");
                }
            }
        }
    }

    public bool AddNode(GraphEntity node)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (string.IsNullOrWhiteSpace(node.EntityId))
        {
            IsValid = false;
            ValidationErrors.Add("Attempted to add node with empty or null EntityId.");
            return false;
        }

        if (_nodes.Count >= MaxGraphNodes && !_nodes.ContainsKey(node.EntityId))
        {
            IsResourceBounded = true;
            IsValid = false;
            ValidationErrors.Add($"Graph exceeded maximum permitted node limit of {MaxGraphNodes}.");
            return false;
        }

        return _nodes.TryAdd(node.EntityId, node);
    }

    public GraphEntity? GetNode(string entityId)
    {
        if (string.IsNullOrWhiteSpace(entityId)) return null;
        _nodes.TryGetValue(entityId, out var node);
        return node;
    }

    public bool TryGetNode(string entityId, out GraphEntity? node)
    {
        if (string.IsNullOrWhiteSpace(entityId))
        {
            node = null;
            return false;
        }
        return _nodes.TryGetValue(entityId, out node);
    }

    public bool ContainsNode(string entityId)
    {
        if (string.IsNullOrWhiteSpace(entityId)) return false;
        return _nodes.ContainsKey(entityId);
    }

    public bool AddEdge(GraphEdge edge)
    {
        ArgumentNullException.ThrowIfNull(edge);

        if (string.IsNullOrWhiteSpace(edge.SourceEntityId) || string.IsNullOrWhiteSpace(edge.TargetEntityId))
        {
            IsValid = false;
            ValidationErrors.Add($"Edge {edge.EdgeId} has null or empty endpoint.");
            return false;
        }

        // Ensure both vertices exist in graph
        if (!_nodes.ContainsKey(edge.SourceEntityId) || !_nodes.ContainsKey(edge.TargetEntityId))
        {
            return false;
        }

        lock (_edgeLock)
        {
            if (_edges.Count >= MaxGraphEdges)
            {
                IsResourceBounded = true;
                IsValid = false;
                ValidationErrors.Add($"Graph exceeded maximum permitted edge limit of {MaxGraphEdges}.");
                return false;
            }

            // Avoid duplicate identical edges
            bool exists = _edges.Any(e =>
                e.SourceEntityId.Equals(edge.SourceEntityId, StringComparison.OrdinalIgnoreCase) &&
                e.TargetEntityId.Equals(edge.TargetEntityId, StringComparison.OrdinalIgnoreCase) &&
                e.Type == edge.Type);

            if (exists) return false;

            _edges.Add(edge);
        }

        var outList = _outgoing.GetOrAdd(edge.SourceEntityId, _ => new List<GraphEdge>());
        lock (outList)
        {
            outList.Add(edge);
        }

        var inList = _incoming.GetOrAdd(edge.TargetEntityId, _ => new List<GraphEdge>());
        lock (inList)
        {
            inList.Add(edge);
        }

        return true;
    }

    public bool RemoveEdge(string edgeId)
    {
        if (string.IsNullOrWhiteSpace(edgeId)) return false;

        lock (_edgeLock)
        {
            var edge = _edges.FirstOrDefault(e => e.EdgeId.Equals(edgeId, StringComparison.OrdinalIgnoreCase));
            if (edge == null) return false;

            _edges.Remove(edge);

            if (_outgoing.TryGetValue(edge.SourceEntityId, out var outList))
            {
                lock (outList) outList.RemoveAll(e => e.EdgeId.Equals(edgeId, StringComparison.OrdinalIgnoreCase));
            }
            if (_incoming.TryGetValue(edge.TargetEntityId, out var inList))
            {
                lock (inList) inList.RemoveAll(e => e.EdgeId.Equals(edgeId, StringComparison.OrdinalIgnoreCase));
            }
            return true;
        }
    }

    public bool RemoveEdge(string sourceEntityId, string targetEntityId, EdgeType type)
    {
        if (string.IsNullOrWhiteSpace(sourceEntityId) || string.IsNullOrWhiteSpace(targetEntityId)) return false;

        lock (_edgeLock)
        {
            var edge = _edges.FirstOrDefault(e =>
                e.SourceEntityId.Equals(sourceEntityId, StringComparison.OrdinalIgnoreCase) &&
                e.TargetEntityId.Equals(targetEntityId, StringComparison.OrdinalIgnoreCase) &&
                e.Type == type);

            if (edge == null) return false;
            return RemoveEdge(edge.EdgeId);
        }
    }

    public bool RemoveNode(string entityId)
    {
        if (string.IsNullOrWhiteSpace(entityId)) return false;

        if (!_nodes.TryRemove(entityId, out _))
            return false;

        // Clean up connected edges
        lock (_edgeLock)
        {
            var connectedEdges = _edges.Where(e =>
                e.SourceEntityId.Equals(entityId, StringComparison.OrdinalIgnoreCase) ||
                e.TargetEntityId.Equals(entityId, StringComparison.OrdinalIgnoreCase)).ToList();

            foreach (var edge in connectedEdges)
            {
                RemoveEdge(edge.EdgeId);
            }
        }

        return true;
    }

    public void Clear()
    {
        _nodes.Clear();
        lock (_edgeLock)
        {
            _edges.Clear();
        }
        _outgoing.Clear();
        _incoming.Clear();
        ValidationErrors.Clear();
        IsValid = true;
        IsResourceBounded = false;
    }

    public IReadOnlyList<GraphEdge> GetOutgoingEdges(string entityId)
    {
        if (string.IsNullOrWhiteSpace(entityId)) return Array.Empty<GraphEdge>();
        if (_outgoing.TryGetValue(entityId, out var list))
        {
            lock (list) return list.ToList();
        }
        return Array.Empty<GraphEdge>();
    }

    public IReadOnlyList<GraphEdge> GetIncomingEdges(string entityId)
    {
        if (string.IsNullOrWhiteSpace(entityId)) return Array.Empty<GraphEdge>();
        if (_incoming.TryGetValue(entityId, out var list))
        {
            lock (list) return list.ToList();
        }
        return Array.Empty<GraphEdge>();
    }

    /// <summary>
    /// Creates an EvidenceCluster node grouping multiple independent, verified observations.
    /// Preserves stable identifier, member node IDs, relationship basis, confidence, and uncertainty notes.
    /// </summary>
    public GraphEntity? CreateEvidenceCluster(
        string clusterId,
        string title,
        string relationshipBasis,
        IEnumerable<string> memberEntityIds,
        ConfidenceLevel confidence = ConfidenceLevel.Certain,
        string? uncertaintyOrAmbiguity = null,
        string? provenance = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clusterId);
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentException.ThrowIfNullOrWhiteSpace(relationshipBasis);

        var validMembers = memberEntityIds?.Where(m => ContainsNode(m)).Distinct(StringComparer.OrdinalIgnoreCase).ToList() ?? new List<string>();
        if (validMembers.Count == 0)
        {
            return null;
        }

        var clusterEntity = new GraphEntity
        {
            EntityId = clusterId,
            Type = EntityType.EvidenceCluster,
            FirstObservedUtc = DateTimeOffset.UtcNow,
            LastObservedUtc = DateTimeOffset.UtcNow,
            ProvenanceSources = { provenance ?? "EvidenceClusterGrouping" },
            Properties =
            {
                ["Title"] = title,
                ["RelationshipBasis"] = relationshipBasis,
                ["Confidence"] = confidence.ToString(),
                ["Uncertainty"] = uncertaintyOrAmbiguity ?? string.Empty,
                ["MemberCount"] = validMembers.Count.ToString(),
                ["Members"] = string.Join(",", validMembers)
            }
        };

        if (!AddNode(clusterEntity))
        {
            return GetNode(clusterId);
        }

        foreach (var memberId in validMembers)
        {
            AddEdge(new GraphEdge
            {
                SourceEntityId = memberId,
                TargetEntityId = clusterId,
                Type = EdgeType.DerivedFrom,
                Confidence = confidence,
                AssertedRelationship = $"Member of evidence cluster '{title}': {relationshipBasis}",
                Limitations = uncertaintyOrAmbiguity ?? string.Empty,
                Provenance = provenance ?? "EvidenceClusterGrouping"
            });
        }

        return clusterEntity;
    }

    /// <summary>
    /// Validates graph structure: ensures all edge endpoints exist, verifies cluster integrity,
    /// and checks resource bounds.
    /// </summary>
    public bool Validate(out List<string> errors)
    {
        errors = new List<string>();

        if (IsResourceBounded)
        {
            errors.Add($"Graph exceeded resource bounds (Nodes: {NodeCount}/{MaxGraphNodes}, Edges: {EdgeCount}/{MaxGraphEdges}).");
        }

        lock (_edgeLock)
        {
            foreach (var edge in _edges)
            {
                if (!_nodes.ContainsKey(edge.SourceEntityId))
                {
                    errors.Add($"Edge '{edge.EdgeId}' references nonexistent source node '{edge.SourceEntityId}'.");
                }
                if (!_nodes.ContainsKey(edge.TargetEntityId))
                {
                    errors.Add($"Edge '{edge.EdgeId}' references nonexistent target node '{edge.TargetEntityId}'.");
                }
            }
        }

        // Validate cluster nodes have valid member edges
        var clusters = _nodes.Values.Where(n => n.Type == EntityType.EvidenceCluster);
        foreach (var cluster in clusters)
        {
            var incoming = GetIncomingEdges(cluster.EntityId);
            if (!incoming.Any(e => e.Type == EdgeType.DerivedFrom || e.Type == EdgeType.Corroborates))
            {
                errors.Add($"EvidenceCluster '{cluster.EntityId}' has no corroborating or member incoming edges.");
            }
        }

        if (errors.Count > 0)
        {
            IsValid = false;
            foreach (var err in errors)
            {
                if (!ValidationErrors.Contains(err))
                    ValidationErrors.Add(err);
            }
            return false;
        }

        return true;
    }

    /// <summary>
    /// Executes a bounded Breadth-First Search (BFS) starting from seedNodeId up to maxDepth hops (strictly capped at k <= 4).
    /// Immune to cycles and combinatorial explosion.
    /// </summary>
    public IReadOnlyList<GraphEntity> Traverse(
        string seedNodeId,
        int maxDepth = DefaultMaxTraversalDepth,
        Func<GraphEdge, bool>? edgeFilter = null)
    {
        if (!_nodes.TryGetValue(seedNodeId, out var seedNode))
            return Array.Empty<GraphEntity>();

        int effectiveMaxDepth = Math.Clamp(maxDepth, 1, DefaultMaxTraversalDepth);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { seedNodeId };
        var result = new List<GraphEntity>();
        var queue = new Queue<(string NodeId, int Depth)>();
        queue.Enqueue((seedNodeId, 0));

        while (queue.Count > 0)
        {
            var (currentId, currentDepth) = queue.Dequeue();

            if (currentDepth >= effectiveMaxDepth)
                continue;

            var outgoing = GetOutgoingEdges(currentId);
            foreach (var edge in outgoing)
            {
                if (edgeFilter != null && !edgeFilter(edge))
                    continue;

                if (visited.Add(edge.TargetEntityId))
                {
                    if (_nodes.TryGetValue(edge.TargetEntityId, out var targetNode))
                    {
                        result.Add(targetNode);
                        queue.Enqueue((edge.TargetEntityId, currentDepth + 1));
                    }
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Checks whether a directed or undirected path exists between two nodes within bounded depth k <= 4.
    /// </summary>
    public bool HasRelationship(
        string startNodeId,
        string targetNodeId,
        int maxDepth = DefaultMaxTraversalDepth,
        Func<GraphEdge, bool>? edgeFilter = null)
    {
        if (string.IsNullOrWhiteSpace(startNodeId) || string.IsNullOrWhiteSpace(targetNodeId))
            return false;

        if (startNodeId.Equals(targetNodeId, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!ContainsNode(startNodeId) || !ContainsNode(targetNodeId))
            return false;

        int effectiveMaxDepth = Math.Clamp(maxDepth, 1, DefaultMaxTraversalDepth);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { startNodeId };
        var queue = new Queue<(string NodeId, int Depth)>();
        queue.Enqueue((startNodeId, 0));

        while (queue.Count > 0)
        {
            var (currentId, currentDepth) = queue.Dequeue();
            if (currentDepth >= effectiveMaxDepth)
                continue;

            // Check outgoing edges
            foreach (var edge in GetOutgoingEdges(currentId))
            {
                if (edgeFilter != null && !edgeFilter(edge))
                    continue;

                if (edge.TargetEntityId.Equals(targetNodeId, StringComparison.OrdinalIgnoreCase))
                    return true;

                if (visited.Add(edge.TargetEntityId))
                {
                    queue.Enqueue((edge.TargetEntityId, currentDepth + 1));
                }
            }

            // Check incoming edges (bidirectional relationship query)
            foreach (var edge in GetIncomingEdges(currentId))
            {
                if (edgeFilter != null && !edgeFilter(edge))
                    continue;

                if (edge.SourceEntityId.Equals(targetNodeId, StringComparison.OrdinalIgnoreCase))
                    return true;

                if (visited.Add(edge.SourceEntityId))
                {
                    queue.Enqueue((edge.SourceEntityId, currentDepth + 1));
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Finds all directed paths between two nodes within bounded depth k <= 4.
    /// </summary>
    public IReadOnlyList<IReadOnlyList<GraphEdge>> FindPaths(string startNodeId, string targetNodeId, int maxDepth = DefaultMaxTraversalDepth)
    {
        var paths = new List<IReadOnlyList<GraphEdge>>();
        if (!_nodes.ContainsKey(startNodeId) || !_nodes.ContainsKey(targetNodeId))
            return paths;

        int effectiveMaxDepth = Math.Clamp(maxDepth, 1, DefaultMaxTraversalDepth);
        var currentPath = new List<GraphEdge>();
        var visitedNodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { startNodeId };
        int iterations = 0;

        DfsPaths(startNodeId, targetNodeId, currentPath, visitedNodes, 0, effectiveMaxDepth, paths, ref iterations);
        return paths;
    }

    private void DfsPaths(
        string currentId,
        string targetId,
        List<GraphEdge> currentPath,
        HashSet<string> visitedNodes,
        int currentDepth,
        int maxDepth,
        List<IReadOnlyList<GraphEdge>> paths,
        ref int iterations)
    {
        if (++iterations > MaxPathSearchIterations)
            return;

        if (currentId.Equals(targetId, StringComparison.OrdinalIgnoreCase))
        {
            if (currentPath.Count > 0)
            {
                paths.Add(currentPath.ToList());
            }
            return;
        }

        if (currentDepth >= maxDepth)
            return;

        foreach (var edge in GetOutgoingEdges(currentId))
        {
            if (!visitedNodes.Contains(edge.TargetEntityId))
            {
                visitedNodes.Add(edge.TargetEntityId);
                currentPath.Add(edge);

                DfsPaths(edge.TargetEntityId, targetId, currentPath, visitedNodes, currentDepth + 1, maxDepth, paths, ref iterations);

                currentPath.RemoveAt(currentPath.Count - 1);
                visitedNodes.Remove(edge.TargetEntityId);
            }
        }
    }
}
