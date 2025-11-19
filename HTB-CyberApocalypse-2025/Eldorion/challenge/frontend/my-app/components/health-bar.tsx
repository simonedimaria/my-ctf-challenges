interface HealthBarProps {
  currentHealth: number
  maxHealth: number
  isEnemy: boolean
}

export default function HealthBar({ currentHealth, maxHealth, isEnemy }: HealthBarProps) {
  const healthPercentage = Math.max(0, Math.min(100, (currentHealth / maxHealth) * 100))

  // Determine color based on health percentage
  let healthColor = "bg-green-500"
  if (healthPercentage < 25) {
    healthColor = "bg-red-500"
  } else if (healthPercentage < 50) {
    healthColor = "bg-yellow-500"
  }

  return (
    <div className="flex items-center gap-2">
      <div className="relative w-32 h-4 bg-gray-800 border-2 border-gray-900 rounded-sm overflow-hidden">
        <div
          className={`absolute top-0 left-0 h-full ${healthColor} transition-all duration-300`}
          style={{ width: `${healthPercentage}%` }}
        ></div>
        {/* Pixelated effect overlay */}
        <div className="absolute inset-0 bg-[url('/pixel-pattern.png')] bg-repeat opacity-20 pixelated"></div>
      </div>
      <span className="text-white font-pixel">
        {currentHealth}/{maxHealth}
      </span>
    </div>
  )
}

