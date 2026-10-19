import cytoscape, { type Core } from "cytoscape";
import { useEffect, useRef } from "react";
import type { GraphData } from "../api";
import { PROVENANCE_COLOR } from "../format";

const NODE_COLOR: Record<string, string> = { host: "#ff922b", image: "#74c0fc", account: "#b197fc", script: "#ffe066" };

/** What the store has learned around one host. Labels are set as data (text), never as HTML. */
export default function Graph({ data, height = 460 }: { data: GraphData; height?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    cy.current?.destroy();
    cy.current = cytoscape({
      container: ref.current,
      elements: [
        ...data.nodes.map((n) => ({ data: { id: n.id, label: n.label, kind: n.type } })),
        ...data.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, prov: e.learned_from, label: e.type } })),
      ],
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-size": 9,
            color: "#ced4da",
            "text-valign": "bottom",
            "text-margin-y": 3,
            width: 12,
            height: 12,
            "background-color": (n: cytoscape.NodeSingular) => NODE_COLOR[String(n.data("kind"))] ?? "#868e96",
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.7,
            "line-color": (e: cytoscape.EdgeSingular) => PROVENANCE_COLOR[String(e.data("prov"))] ?? "#868e96",
            "target-arrow-color": (e: cytoscape.EdgeSingular) => PROVENANCE_COLOR[String(e.data("prov"))] ?? "#868e96",
          },
        },
      ],
      layout: { name: "cose", animate: false, nodeRepulsion: () => 9000 },
      wheelSensitivity: 0.3,
    });
    return () => {
      cy.current?.destroy();
      cy.current = null;
    };
  }, [data]);

  return <div ref={ref} style={{ height, width: "100%", border: "1px solid var(--mantine-color-dark-4)", borderRadius: 8 }} />;
}
