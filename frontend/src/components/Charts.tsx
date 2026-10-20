// Charts for the console. Emphasis encoding: the routine majority in gray, cases for an analyst in
// colour (dataviz validator, dark, surface #1c1c1c: CVD dE 10.7, normal-vision dE 17.8, contrast >= 3:1;
// the chroma check flags the gray, as intended for emphasis).
import ReactECharts from "echarts-for-react";

const SURFACE = "#1c1c1c";
const SERIES_1 = "#7a7a7a"; // closed automatically (the routine majority)
const SERIES_2 = "#d95926"; // sent to an analyst
const INK_2 = "#a6a6a6";
const MUTED = "#767676";
const GRID = "#2b2b2b";
const TIP = { backgroundColor: "#262626", borderColor: "#3a3a3a", textStyle: { color: "#ececec", fontSize: 12 } };

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
          ...TIP,
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
          axisPointer: { type: "shadow", shadowStyle: { color: "rgba(255,255,255,0.05)" } },
          ...TIP,
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
          axisLine: { lineStyle: { color: "#3a3a3a" } },
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
