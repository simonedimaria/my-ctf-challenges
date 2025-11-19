interface ManaBarProps {
  currentMana: number
  maxMana: number
  isEnemy: boolean
}

export default function ManaBar({ currentMana, maxMana, isEnemy }: ManaBarProps) {
  const manaPercentage = Math.max(0, Math.min(100, (currentMana / maxMana) * 100))

  return (
    <div className="flex items-center gap-2">
      <div className="relative w-24 h-3 bg-gray-800 border-2 border-gray-900 rounded-sm overflow-hidden">
        <div
          className="absolute top-0 left-0 h-full bg-blue-500 transition-all duration-300"
          style={{ width: `${manaPercentage}%` }}
        ></div>
        {/* Pixelated effect overlay */}
        <div className="absolute inset-0 bg-[url('/pixel-pattern.png')] bg-repeat opacity-20 pixelated"></div>
      </div>
      <span className="text-white font-pixel">
        {currentMana}/{maxMana}
      </span>
    </div>
  )
}

