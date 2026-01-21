import { useState, useMemo } from 'react'
import { X, Search, Check, ChevronDown } from 'lucide-react'
import { getCountryFlag, cn } from '@/lib/utils'
import { useDeferredSearch } from '@/hooks/useReact19'

// Comprehensive list of countries with ISO 3166-1 alpha-2 codes
const COUNTRIES: Array<{ code: string; name: string }> = [
  { code: 'AF', name: 'Afghanistan' },
  { code: 'AL', name: 'Albania' },
  { code: 'DZ', name: 'Algeria' },
  { code: 'AD', name: 'Andorra' },
  { code: 'AO', name: 'Angola' },
  { code: 'AR', name: 'Argentina' },
  { code: 'AM', name: 'Armenia' },
  { code: 'AU', name: 'Australia' },
  { code: 'AT', name: 'Austria' },
  { code: 'AZ', name: 'Azerbaijan' },
  { code: 'BH', name: 'Bahrain' },
  { code: 'BD', name: 'Bangladesh' },
  { code: 'BY', name: 'Belarus' },
  { code: 'BE', name: 'Belgium' },
  { code: 'BA', name: 'Bosnia and Herzegovina' },
  { code: 'BR', name: 'Brazil' },
  { code: 'BG', name: 'Bulgaria' },
  { code: 'CA', name: 'Canada' },
  { code: 'CL', name: 'Chile' },
  { code: 'CN', name: 'China' },
  { code: 'CO', name: 'Colombia' },
  { code: 'HR', name: 'Croatia' },
  { code: 'CY', name: 'Cyprus' },
  { code: 'CZ', name: 'Czech Republic' },
  { code: 'DK', name: 'Denmark' },
  { code: 'EG', name: 'Egypt' },
  { code: 'EE', name: 'Estonia' },
  { code: 'FI', name: 'Finland' },
  { code: 'FR', name: 'France' },
  { code: 'GE', name: 'Georgia' },
  { code: 'DE', name: 'Germany' },
  { code: 'GR', name: 'Greece' },
  { code: 'HK', name: 'Hong Kong' },
  { code: 'HU', name: 'Hungary' },
  { code: 'IS', name: 'Iceland' },
  { code: 'IN', name: 'India' },
  { code: 'ID', name: 'Indonesia' },
  { code: 'IR', name: 'Iran' },
  { code: 'IQ', name: 'Iraq' },
  { code: 'IE', name: 'Ireland' },
  { code: 'IL', name: 'Israel' },
  { code: 'IT', name: 'Italy' },
  { code: 'JP', name: 'Japan' },
  { code: 'JO', name: 'Jordan' },
  { code: 'KZ', name: 'Kazakhstan' },
  { code: 'KE', name: 'Kenya' },
  { code: 'KP', name: 'North Korea' },
  { code: 'KR', name: 'South Korea' },
  { code: 'KW', name: 'Kuwait' },
  { code: 'LV', name: 'Latvia' },
  { code: 'LB', name: 'Lebanon' },
  { code: 'LT', name: 'Lithuania' },
  { code: 'LU', name: 'Luxembourg' },
  { code: 'MY', name: 'Malaysia' },
  { code: 'MX', name: 'Mexico' },
  { code: 'MD', name: 'Moldova' },
  { code: 'MC', name: 'Monaco' },
  { code: 'MA', name: 'Morocco' },
  { code: 'NL', name: 'Netherlands' },
  { code: 'NZ', name: 'New Zealand' },
  { code: 'NG', name: 'Nigeria' },
  { code: 'NO', name: 'Norway' },
  { code: 'PK', name: 'Pakistan' },
  { code: 'PA', name: 'Panama' },
  { code: 'PH', name: 'Philippines' },
  { code: 'PL', name: 'Poland' },
  { code: 'PT', name: 'Portugal' },
  { code: 'QA', name: 'Qatar' },
  { code: 'RO', name: 'Romania' },
  { code: 'RU', name: 'Russia' },
  { code: 'SA', name: 'Saudi Arabia' },
  { code: 'RS', name: 'Serbia' },
  { code: 'SG', name: 'Singapore' },
  { code: 'SK', name: 'Slovakia' },
  { code: 'SI', name: 'Slovenia' },
  { code: 'ZA', name: 'South Africa' },
  { code: 'ES', name: 'Spain' },
  { code: 'SE', name: 'Sweden' },
  { code: 'CH', name: 'Switzerland' },
  { code: 'SY', name: 'Syria' },
  { code: 'TW', name: 'Taiwan' },
  { code: 'TH', name: 'Thailand' },
  { code: 'TR', name: 'Turkey' },
  { code: 'UA', name: 'Ukraine' },
  { code: 'AE', name: 'United Arab Emirates' },
  { code: 'GB', name: 'United Kingdom' },
  { code: 'US', name: 'United States' },
  { code: 'UY', name: 'Uruguay' },
  { code: 'UZ', name: 'Uzbekistan' },
  { code: 'VE', name: 'Venezuela' },
  { code: 'VN', name: 'Vietnam' },
  { code: 'YE', name: 'Yemen' },
]

interface CountrySelectorProps {
  selectedCountries: string[]
  onChange: (countries: string[]) => void
  placeholder?: string
  maxHeight?: string
  disabled?: boolean
  className?: string
}

export function CountrySelector({
  selectedCountries,
  onChange,
  placeholder = 'Select countries...',
  maxHeight = 'max-h-60',
  disabled = false,
  className = '',
}: CountrySelectorProps) {
  const [isOpen, setIsOpen] = useState(false)
  // v3.58.108: Use deferred search for smoother filtering
  const { searchValue: search, setSearchValue: setSearch, deferredSearch, isStale } = useDeferredSearch('')

  const filteredCountries = useMemo(() => {
    if (!deferredSearch) return COUNTRIES
    const searchLower = deferredSearch.toLowerCase()
    return COUNTRIES.filter(
      (c) =>
        c.name.toLowerCase().includes(searchLower) ||
        c.code.toLowerCase().includes(searchLower)
    )
  }, [deferredSearch])

  const toggleCountry = (code: string) => {
    if (selectedCountries.includes(code)) {
      onChange(selectedCountries.filter((c) => c !== code))
    } else {
      onChange([...selectedCountries, code])
    }
  }

  const removeCountry = (code: string, e: React.MouseEvent) => {
    e.stopPropagation()
    onChange(selectedCountries.filter((c) => c !== code))
  }

  const getCountryByCode = (code: string) =>
    COUNTRIES.find((c) => c.code === code)

  return (
    <div className={cn('relative', className)}>
      {/* Selected countries badges and trigger */}
      <div
        className={cn(
          'min-h-[42px] p-2 rounded-md border border-gray-700 bg-gray-800 cursor-pointer',
          'flex flex-wrap gap-1.5 items-center',
          disabled && 'opacity-50 cursor-not-allowed',
          isOpen && 'ring-2 ring-blue-500 border-blue-500'
        )}
        onClick={() => !disabled && setIsOpen(!isOpen)}
      >
        {selectedCountries.length === 0 ? (
          <span className="text-gray-500 text-sm">{placeholder}</span>
        ) : (
          selectedCountries.map((code) => {
            const country = getCountryByCode(code)
            return (
              <span
                key={code}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 text-sm"
              >
                <span>{getCountryFlag(code)}</span>
                <span>{country?.name || code}</span>
                <button
                  onClick={(e) => removeCountry(code, e)}
                  className="ml-0.5 hover:text-blue-200"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            )
          })
        )}
        <ChevronDown
          className={cn(
            'w-4 h-4 text-gray-500 ml-auto transition-transform',
            isOpen && 'transform rotate-180'
          )}
        />
      </div>

      {/* Dropdown */}
      {isOpen && !disabled && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-40"
            onClick={() => setIsOpen(false)}
          />

          {/* Dropdown content */}
          <div className="absolute z-50 w-full mt-1 rounded-md border border-gray-700 bg-gray-800 shadow-xl">
            {/* Search */}
            <div className="p-2 border-b border-gray-700">
              <div className="relative">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  type="text"
                  placeholder="Search countries..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 rounded bg-gray-700 border border-gray-600 text-white text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
                  onClick={(e) => e.stopPropagation()}
                  autoFocus
                />
              </div>
            </div>

            {/* Country list - v3.58.108: opacity when filtering */}
            <div className={cn('overflow-y-auto transition-opacity', maxHeight, isStale && 'opacity-60')}>
              {filteredCountries.length === 0 ? (
                <div className="p-3 text-center text-gray-500 text-sm">
                  No countries found
                </div>
              ) : (
                filteredCountries.map((country) => {
                  const isSelected = selectedCountries.includes(country.code)
                  return (
                    <div
                      key={country.code}
                      className={cn(
                        'flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-gray-700',
                        isSelected && 'bg-blue-500/10'
                      )}
                      onClick={() => toggleCountry(country.code)}
                    >
                      <span className="text-lg">{getCountryFlag(country.code)}</span>
                      <span className="flex-1 text-sm text-gray-200">
                        {country.name}
                      </span>
                      <span className="text-xs text-gray-500 font-mono">
                        {country.code}
                      </span>
                      {isSelected && (
                        <Check className="w-4 h-4 text-blue-400" />
                      )}
                    </div>
                  )
                })
              )}
            </div>

            {/* Quick actions */}
            <div className="p-2 border-t border-gray-700 flex gap-2">
              <button
                className="flex-1 px-2 py-1 text-xs text-gray-400 hover:text-white hover:bg-gray-700 rounded"
                onClick={() => onChange([])}
              >
                Clear All
              </button>
              <button
                className="flex-1 px-2 py-1 text-xs text-gray-400 hover:text-white hover:bg-gray-700 rounded"
                onClick={() => onChange(['FR', 'BE', 'LU', 'CH', 'DE', 'NL'])}
              >
                Western EU
              </button>
              <button
                className="flex-1 px-2 py-1 text-xs text-gray-400 hover:text-white hover:bg-gray-700 rounded"
                onClick={() => {
                  const euCountries = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE']
                  onChange(euCountries)
                }}
              >
                All EU
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export { COUNTRIES }
