using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using MinecraftSsForensics.Scanner.Models;

namespace MinecraftSsForensics.Scanner.Graph;

/// <summary>
/// Base class for all vertices in the Directed Attributed Evidence Graph.
/// </summary>
public class GraphEntity
{
    public string EntityId { get; set; } = string.Empty;
    public EntityType Type { get; set; } = EntityType.RawObservation;
    public DateTimeOffset FirstObservedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastObservedUtc { get; set; } = DateTimeOffset.UtcNow;
    public Dictionary<string, string> Properties { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> ProvenanceSources { get; set; } = new();

    public GraphEntity() { }

    [JsonConstructor]
    public GraphEntity(string entityId, EntityType type)
    {
        EntityId = entityId;
        Type = type;
    }

    public override string ToString() => $"[{Type}] {EntityId}";
}

/// <summary>
/// Directed attributed edge connecting two entities in the Evidence Graph.
/// </summary>
public class GraphEdge
{
    public string EdgeId { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public string SourceEntityId { get; set; } = string.Empty;
    public string TargetEntityId { get; set; } = string.Empty;
    public EdgeType Type { get; set; }
    public ConfidenceLevel Confidence { get; set; } = ConfidenceLevel.Medium;
    public string Provenance { get; set; } = string.Empty;
    public string AssertedRelationship { get; set; } = string.Empty;
    public string Limitations { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public GraphEdge() { }

    [JsonConstructor]
    public GraphEdge(string sourceEntityId, string targetEntityId, EdgeType type)
    {
        SourceEntityId = sourceEntityId;
        TargetEntityId = targetEntityId;
        Type = type;
    }

    public override string ToString() => $"{SourceEntityId} -[:{Type}]-> {TargetEntityId}";
}
