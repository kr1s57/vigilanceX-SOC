import { useEffect, useState, useCallback, useMemo } from 'react'
import { GeoJSON } from 'react-leaflet'
import type { GeoJsonObject, Feature, Geometry } from 'geojson'
import type { Layer, PathOptions } from 'leaflet'
import { getThreatColor, type CountryAttackStats } from '@/stores/attackMapStore'

interface CountryLayerProps {
  countryStats: Map<string, CountryAttackStats>
  onCountryClick: (countryCode: string) => void
}

// Simple country boundaries (simplified for performance)
// Using Natural Earth 110m simplified data
const COUNTRY_BOUNDS_URL = 'https://raw.githubusercontent.com/datasets/geo-countries/master/data/countries.geojson'

export function CountryLayer({ countryStats, onCountryClick }: CountryLayerProps) {
  const [geoData, setGeoData] = useState<GeoJsonObject | null>(null)
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null)

  // Fetch GeoJSON data
  useEffect(() => {
    const fetchGeoJSON = async () => {
      try {
        // Try to get from cache first
        const cached = sessionStorage.getItem('countriesGeoJSON')
        if (cached) {
          setGeoData(JSON.parse(cached))
          return
        }

        const response = await fetch(COUNTRY_BOUNDS_URL)
        const data = await response.json()

        // Cache for the session
        try {
          sessionStorage.setItem('countriesGeoJSON', JSON.stringify(data))
        } catch {
          // Storage might be full, ignore
        }

        setGeoData(data)
      } catch (err) {
        console.error('Failed to fetch country GeoJSON:', err)
      }
    }

    fetchGeoJSON()
  }, [])

  // Style function for countries
  const style = useCallback((feature: Feature<Geometry> | undefined): PathOptions => {
    if (!feature?.properties) return getDefaultStyle()

    const countryCode = feature.properties.ISO_A2 || feature.properties.iso_a2
    const stats = countryStats.get(countryCode)
    const isHovered = hoveredCountry === countryCode

    if (!stats || stats.count === 0) {
      return {
        fillColor: isHovered ? 'rgba(255, 255, 255, 0.1)' : 'transparent',
        fillOpacity: isHovered ? 0.3 : 0,
        color: 'rgba(75, 85, 99, 0.3)',
        weight: isHovered ? 1.5 : 0.5,
        opacity: 0.5,
      }
    }

    const threatColor = getThreatColor(stats.threatLevel)

    return {
      fillColor: threatColor,
      fillOpacity: isHovered ? 0.9 : 0.6,
      color: isHovered ? '#fff' : threatColor,
      weight: isHovered ? 2 : 1,
      opacity: isHovered ? 1 : 0.8,
    }
  }, [countryStats, hoveredCountry])

  // Event handlers for each feature
  const onEachFeature = useCallback((feature: Feature<Geometry>, layer: Layer) => {
    const countryCode = feature.properties?.ISO_A2 || feature.properties?.iso_a2
    const countryName = feature.properties?.ADMIN || feature.properties?.name

    layer.on({
      mouseover: () => {
        setHoveredCountry(countryCode)
      },
      mouseout: () => {
        setHoveredCountry(null)
      },
      click: () => {
        if (countryCode) {
          onCountryClick(countryCode)
        }
      },
    })

    // Add tooltip with country info
    const stats = countryStats.get(countryCode)
    if (stats && stats.count > 0) {
      layer.bindTooltip(
        `<div class="font-sans">
          <div class="font-bold text-sm">${countryName || countryCode}</div>
          <div class="text-xs mt-1">
            <div>Attacks: <span class="font-semibold text-red-400">${stats.count.toLocaleString()}</span></div>
            <div>Unique IPs: <span class="font-semibold text-cyan-400">${stats.uniqueIps.toLocaleString()}</span></div>
          </div>
          <div class="text-[10px] mt-1 text-gray-400">Click for details</div>
        </div>`,
        {
          className: 'attack-map-tooltip',
          sticky: true,
        }
      )
    }
  }, [countryStats, onCountryClick])

  // Memoize the GeoJSON key to force re-render when stats change
  const geoJsonKey = useMemo(() => {
    const statsHash = Array.from(countryStats.entries())
      .map(([k, v]) => `${k}:${v.count}`)
      .join(',')
    return `geojson-${statsHash}-${hoveredCountry}`
  }, [countryStats, hoveredCountry])

  if (!geoData) return null

  return (
    <>
      <GeoJSON
        key={geoJsonKey}
        data={geoData}
        style={style}
        onEachFeature={onEachFeature}
      />

      {/* Custom tooltip styles */}
      <style>{`
        .attack-map-tooltip {
          background: rgba(0, 0, 0, 0.85) !important;
          backdrop-filter: blur(8px);
          border: 1px solid rgba(255, 255, 255, 0.1) !important;
          border-radius: 8px !important;
          padding: 8px 12px !important;
          color: white !important;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5) !important;
        }
        .attack-map-tooltip::before {
          border-top-color: rgba(0, 0, 0, 0.85) !important;
        }
        .leaflet-tooltip-left.attack-map-tooltip::before {
          border-left-color: rgba(0, 0, 0, 0.85) !important;
        }
        .leaflet-tooltip-right.attack-map-tooltip::before {
          border-right-color: rgba(0, 0, 0, 0.85) !important;
        }
      `}</style>
    </>
  )
}

function getDefaultStyle(): PathOptions {
  return {
    fillColor: 'transparent',
    fillOpacity: 0,
    color: 'rgba(75, 85, 99, 0.3)',
    weight: 0.5,
    opacity: 0.3,
  }
}
