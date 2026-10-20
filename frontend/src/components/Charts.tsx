// Charts for the console. Colours: two categorical slots validated on the console surface
// (dataviz validator, dark, surface #111a2b: CVD dE 26.8, normal-vision dE 31.8, contrast >= 3:1).
import ReactECharts from "echarts-for-react";

const SURFACE = "#111a2b";
const SERIES_1 = "#3987e5"; // closed automatically
const SERIES_2 = "#d95926"; // sent to an analyst
const INK_2 = "#a8b3c4";
const MUTED = "#7b8798";
const GRID = "rgba(148,163,184,0.12)";

/** A one-series trend line for a stat tile (no axes; the tile's number is the headline). */
export function Sparkline({ values, color = SERIES_1, height = 34, label }: { values: number[]; color?: string; height?: number; label: string }) {
  if (values.length < 2) return <div style={{ height }} />;
  return (
    <ReactECharts
      style={{ height, width: "100%" }}
      opts={{ renderer: "svg" }}
      option={{
        animation: false,
        grid: { left: 2, right: 2, top: 4, bottom: 2 },
        xAxis: { type: "category", show: false, data: values.map((_, i) => i) },
        yAxis: { type: "value", show: false, min: 0 },
        tooltip: {
          trigger: "axis",
          axisPointer: { type: "line", lineStyle: { color: MUTED } },
          backgroundColor: "#16223a",
          borderColor: "rgba(148,163,184,0.26)",
          textStyle: { color: "#e6ebf2", fontSize: 11 },
          formatter: (p: { dataIndex: number; value: number }[]) => {
            const back = values.length - 1 - p[0].dataIndex;
            return `${label}: <b>${p[0].value}</b><br/><span style="color:${INK_2}">${back === 0 ? "this hour" : `${back} h ago`}</span>`;
          },
        },
        series: [{
          type: "line", data: values, smooth: false, symbol: "none",
          lineStyle: { width: 2, color }, areaStyle: { color, opacity: 0.12 },
        }],
      }}
    />
  );
}

export interface HourBucket { hour: string; closed_automatically: number; sent_to_analyst: number }

/** Cases opened per stream hour: closed automatically vs sent to an analyst (stacked). */
export function ActivityChart({ hours, height = 230 }: { hours: HourBucket[]; height?: number }) {
  const labels = hours.map((h) => h.hour.slice(11, 13) + ":00");
  return (
    <ReactECharts
      style={{ height, width: "100%" }}
      opts={{ renderer: "svg" }}
      option={{
        animation: false,
        grid: { left: 40, right: 12, top: 34, bottom: 26 },
        legend: {
          top: 0, right: 0, icon: "roundRect", itemWidth: 10, itemHeight: 10,
          textStyle: { color: INK_2, fontSize: 12 },
          data: ["Closed automatically", "Sent to an analyst"],
        },
        tooltip: {
          trigger: "axis",
          axisPointer: { type: "shadow", shadowStyle: { color: "rgba(148,163,184,0.08)" } },
          backgroundColor: "#16223a",
          borderColor: "rgba(148,163,184,0.26)",
          textStyle: { color: "#e6ebf2", fontSize: 12 },
          formatter: (p: { dataIndex: number; seriesName: string; value: number; marker: string }[]) => {
            const h = hours[p[0].dataIndex];
            const total = h.closed_automatically + h.sent_to_analyst;
            return `<b>${h.hour.slice(0, 10)} ${h.hour.slice(11, 16)} UTC</b><br/>` +
              p.map((s) => `${s.marker}${s.seriesName}: <b>${s.value}</b>`).join("<br/>") +
              `<br/><span style="color:${INK_2}">${total} cases opened</span>`;
          },
        },
        xAxis: {
          type: "category", data: labels,
          axisLine: { lineStyle: { color: "rgba(148,163,184,0.3)" } },
          axisTick: { show: false },
          axisLabel: { color: MUTED, fontSize: 11, interval: 2 },
        },
        yAxis: {
          type: "value", minInterval: 1,
          splitLine: { lineStyle: { color: GRID } },
          axisLabel: { color: MUTED, fontSize: 11 },
        },
        series: [
          {
            name: "Closed automatically", type: "bar", stack: "cases", barMaxWidth: 22,
            data: hours.map((h) => h.closed_automatically),
            itemStyle: { color: SERIES_1, borderColor: SURFACE, borderWidth: 1 },
          },
          {
            name: "Sent to an analyst", type: "bar", stack: "cases", barMaxWidth: 22,
            data: hours.map((h) => h.sent_to_analyst),
            itemStyle: { color: SERIES_2, borderColor: SURFACE, borderWidth: 1, borderRadius: [3, 3, 0, 0] },
          },
        ],
      }}
    />
  );
}
