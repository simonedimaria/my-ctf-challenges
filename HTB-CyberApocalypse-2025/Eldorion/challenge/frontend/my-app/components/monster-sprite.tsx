"use client"

import { useEffect, useState } from "react"
import type { Monster } from "@/types/game-types"

interface MonsterSpriteProps {
  monster: Monster
}

export default function MonsterSprite({ monster }: MonsterSpriteProps) {
  const [frame, setFrame] = useState(0)

  // Simple animation effect
  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((prev) => (prev + 1) % 4)
    }, 250)

    return () => clearInterval(interval)
  }, [])

  // Different sprite positions based on monster state
  const getStateClass = () => {
    switch (monster.state) {
      case "attacking":
        return "transform translate-x-2 -translate-y-2 scale-110"
      case "hit":
        return "animate-pulse opacity-70"
      case "defending":
        return "border-4 border-blue-500 rounded-full opacity-80"
      default:
        return `transform translate-y-${frame % 2}`
    }
  }

  return (
    <div className={`relative transition-all duration-150 ${getStateClass()}`}>
      <div className="w-32 h-32 relative">
        {/* Monster sprite */}
        <img
          src={monster.sprite || "/placeholder.svg"}
          alt={monster.name}
          className="w-full h-full object-contain pixelated"
        />

        {/* State effects */}
        {monster.state === "attacking" && (
          <div className="absolute inset-0 bg-yellow-500 opacity-30 animate-pulse"></div>
        )}
        {monster.state === "defending" && (
          <div className="absolute inset-0 border-4 border-blue-400 rounded-full opacity-50"></div>
        )}
      </div>
    </div>
  )
}

