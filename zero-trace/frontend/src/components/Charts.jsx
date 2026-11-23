import { useMemo } from 'react'
import {
  ArcElement, BarElement, CategoryScale, Chart as ChartJS, Filler,
  Legend, LineElement, LinearScale, PointElement, Tooltip,
} from 'chart.js'
import { Bar, Doughnut, Line } from 'react-chartjs-2'

ChartJS.register(ArcElement, BarElement, CategoryScale, Filler, Legend, LineElement, LinearScale, PointElement, Tooltip)

ChartJS.defaults.color = '#8fa3bf'
ChartJS.defaults.font.family = "'Inter', 'Segoe UI', sans-serif"

const RISK_COLORS = {
  critical: '#ff5470',
  high: '#ff9f43',
  medium: '#ffd166',
  low: '#3fd8a4',
  minimal: '#4f7cff',
}

const SEVERITY_COLORS = {
  critical: '#ff5470',
  high: '#ff9f43',
  medium: '#ffd166',
  low: '#3fd8a4',
  info: '#4f7cff',
}

const grid = { color: 'rgba(143, 163, 191, 0.12)', drawTicks: false }
const ticks = { padding: 10 }

export function RiskDoughnut({ distribution = {} }) {
  const levels = ['critical', 'high', 'medium', 'low', 'minimal']
  const values = levels.map((level) => distribution[level] || 0)
  const hasData = values.some(Boolean)
  const data = useMemo(
    () => ({
      labels: levels.map((level) => level.toUpperCase()),
      datasets: [
        {
          data: hasData ? values : [1],
          backgroundColor: hasData ? levels.map((level) => RISK_COLORS[level]) : ['#20304a'],
          borderColor: '#0d1525',
          borderWidth: 3,
          hoverOffset: 6,
        },
      ],
    }),
    [distribution],
  )

  return (
    <div className="chart-wrap doughnut-wrap">
      <Doughnut
        data={data}
        options={{
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: { position: 'right', labels: { boxWidth: 10, boxHeight: 10, usePointStyle: true, padding: 14 } },
            tooltip: { enabled: hasData },
          },
        }}
      />
      <div className="doughnut-center">
        <strong>{values.reduce((total, value) => total + value, 0)}</strong>
        <span>scans</span>
      </div>
    </div>
  )
}

export function SeverityBar({ distribution = {} }) {
  const levels = ['critical', 'high', 'medium', 'low', 'info']
  const data = useMemo(
    () => ({
      labels: levels.map((level) => level[0].toUpperCase() + level.slice(1)),
      datasets: [
        {
          label: 'Findings',
          data: levels.map((level) => distribution[level] || 0),
          backgroundColor: levels.map((level) => SEVERITY_COLORS[level]),
          borderRadius: 6,
          barThickness: 28,
        },
      ],
    }),
    [distribution],
  )

  return (
    <div className="chart-wrap">
      <Bar
        data={data}
        options={{
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false }, ticks },
            y: { beginAtZero: true, grid, ticks: { ...ticks, precision: 0 } },
          },
        }}
      />
    </div>
  )
}

export function RiskTrendLine({ timeline = [] }) {
  const data = useMemo(
    () => ({
      labels: timeline.map((item) => item.date.slice(5, 16).replace('T', ' ')),
      datasets: [
        {
          label: 'Risk score',
          data: timeline.map((item) => item.score),
          borderColor: '#ff9f43',
          backgroundColor: 'rgba(255, 159, 67, 0.14)',
          fill: true,
          tension: 0.35,
          pointRadius: 3,
          pointHoverRadius: 5,
          pointBackgroundColor: '#ff9f43',
        },
      ],
    }),
    [timeline],
  )

  return (
    <div className="chart-wrap">
      <Line
        data={data}
        options={{
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false }, ticks },
            y: { beginAtZero: true, min: 0, max: 100, grid, ticks: { ...ticks, stepSize: 25 } },
          },
        }}
      />
    </div>
  )
}

export function TrendLine({ trend = [] }) {
  const data = useMemo(
    () => ({
      labels: trend.map((item) => item.date.slice(5)),
      datasets: [
        {
          label: 'Scans',
          data: trend.map((item) => item.count),
          borderColor: '#3fd8a4',
          backgroundColor: 'rgba(63, 216, 164, 0.16)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          pointHoverRadius: 5,
          pointBackgroundColor: '#3fd8a4',
        },
      ],
    }),
    [trend],
  )

  return (
    <div className="chart-wrap">
      <Line
        data={data}
        options={{
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false }, ticks },
            y: { beginAtZero: true, grid, ticks: { ...ticks, precision: 0 } },
          },
        }}
      />
    </div>
  )
}
