"use client"

import { useState, useEffect } from "react"
import MonsterSprite from "./monster-sprite"
import HealthBar from "./health-bar"
import ManaBar from "./mana-bar"
import ActionPanel from "./action-panel"
import TurnIndicator from "./turn-indicator"
import BattleLog from "./battle-log"
import type { Monster, Action, BattleState } from "@/types/game-types"

export default function BattleArena() {
  // Initial monster stats
  const [playerMonster, setPlayerMonster] = useState<Monster>({
    name: "Flameheart",
    maxHealth: 100,
    currentHealth: 100,
    maxMana: 50,
    currentMana: 50,
    sprite: "/player-monster.png",
    state: "idle",
  })

  const [enemyMonster, setEnemyMonster] = useState<Monster>({
    name: "Shadowclaw",
    maxHealth: 120,
    currentHealth: 120,
    maxMana: 40,
    currentMana: 40,
    sprite: "/enemy-monster.png",
    state: "idle",
  })

  const [battleState, setBattleState] = useState<BattleState>({
    currentTurn: "player",
    battleLog: ["Battle started! Your turn."],
    isAnimating: false,
  })

  // Available actions for the player
  const actions: Action[] = [
    { name: "Attack", icon: "⚔️", manaCost: 0, damage: 15 },
    { name: "Fireball", icon: "🔥", manaCost: 15, damage: 30 },
    { name: "Heal", icon: "💚", manaCost: 20, damage: -20 },
    { name: "Defend", icon: "🛡️", manaCost: 5, damage: 0 },
  ]

  // Handle player action
  const handleAction = (action: Action) => {
    if (battleState.isAnimating || battleState.currentTurn !== "player") return
    if (playerMonster.currentMana < action.manaCost) {
      setBattleState((prev) => ({
        ...prev,
        battleLog: [`Not enough mana for ${action.name}!`, ...prev.battleLog],
      }))
      return
    }

    // Set animation state
    setBattleState((prev) => ({ ...prev, isAnimating: true }))
    setPlayerMonster((prev) => ({ ...prev, state: "attacking" }))

    // Update player mana
    setPlayerMonster((prev) => ({
      ...prev,
      currentMana: Math.max(0, prev.currentMana - action.manaCost),
    }))

    // Process action effects
    setTimeout(() => {
      if (action.name === "Heal") {
        setPlayerMonster((prev) => ({
          ...prev,
          currentHealth: Math.min(prev.maxHealth, prev.currentHealth - action.damage),
          state: "idle",
        }))
        setBattleState((prev) => ({
          ...prev,
          battleLog: [`You used ${action.name} and recovered ${-action.damage} health!`, ...prev.battleLog],
          isAnimating: false,
          currentTurn: "enemy",
        }))
      } else if (action.name === "Defend") {
        setPlayerMonster((prev) => ({ ...prev, state: "defending" }))
        setBattleState((prev) => ({
          ...prev,
          battleLog: [`You used ${action.name} and prepared to block the next attack!`, ...prev.battleLog],
          isAnimating: false,
          currentTurn: "enemy",
        }))
      } else {
        // Attack actions
        setEnemyMonster((prev) => ({
          ...prev,
          currentHealth: Math.max(0, prev.currentHealth - action.damage),
          state: "hit",
        }))
        setBattleState((prev) => ({
          ...prev,
          battleLog: [`You used ${action.name} and dealt ${action.damage} damage!`, ...prev.battleLog],
          isAnimating: false,
          currentTurn: "enemy",
        }))

        // Reset enemy state after hit animation
        setTimeout(() => {
          setEnemyMonster((prev) => ({ ...prev, state: "idle" }))
          setPlayerMonster((prev) => ({ ...prev, state: "idle" }))
        }, 500)
      }
    }, 800)

    // Enemy turn
    setTimeout(() => {
      enemyTurn()
    }, 2000)
  }

  // Enemy AI turn
  const enemyTurn = () => {
    if (enemyMonster.currentHealth <= 0) return

    setEnemyMonster((prev) => ({ ...prev, state: "attacking" }))

    // Simple AI: randomly choose between attack and special attack
    const attackDamage = Math.random() > 0.7 ? 25 : 15
    const attackName = attackDamage === 25 ? "Dark Slash" : "Claw Attack"
    const manaCost = attackDamage === 25 ? 10 : 0

    // Update enemy mana
    setEnemyMonster((prev) => ({
      ...prev,
      currentMana: Math.max(0, prev.currentMana - manaCost),
    }))

    // Apply damage to player
    setTimeout(() => {
      // Check if player is defending
      const damageReduction = playerMonster.state === "defending" ? 0.5 : 1
      const finalDamage = Math.floor(attackDamage * damageReduction)

      setPlayerMonster((prev) => ({
        ...prev,
        currentHealth: Math.max(0, prev.currentHealth - finalDamage),
        state: "hit",
      }))

      setBattleState((prev) => ({
        ...prev,
        battleLog: [
          `Enemy used ${attackName} and dealt ${finalDamage} damage!${damageReduction < 1 ? " (Reduced by defense)" : ""}`,
          ...prev.battleLog,
        ],
        currentTurn: "player",
      }))

      // Reset states after animation
      setTimeout(() => {
        setPlayerMonster((prev) => ({ ...prev, state: "idle" }))
        setEnemyMonster((prev) => ({ ...prev, state: "idle" }))
      }, 500)
    }, 800)
  }

  // Regenerate some mana each turn
  useEffect(() => {
    if (battleState.currentTurn === "player") {
      setPlayerMonster((prev) => ({
        ...prev,
        currentMana: Math.min(prev.maxMana, prev.currentMana + 5),
      }))
    } else {
      setEnemyMonster((prev) => ({
        ...prev,
        currentMana: Math.min(prev.maxMana, prev.currentMana + 5),
      }))
    }
  }, [battleState.currentTurn])

  return (
    <div className="relative w-full max-w-4xl h-[600px] bg-[#1a1c2c] rounded-lg overflow-hidden border-4 border-[#5d275d] shadow-2xl">
      {/* Pixelated background */}
      <div className="absolute inset-0 bg-[url('/battle-background.png')] bg-cover bg-center pixelated opacity-80"></div>

      {/* Battle arena */}
      <div className="relative z-10 w-full h-full flex flex-col p-4">
        {/* Turn indicator */}
        <TurnIndicator currentTurn={battleState.currentTurn} />

        {/* Enemy monster area */}
        <div className="flex flex-col items-end mb-4">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-white font-pixel">{enemyMonster.name}</span>
            <HealthBar currentHealth={enemyMonster.currentHealth} maxHealth={enemyMonster.maxHealth} isEnemy={true} />
          </div>
          <div className="flex items-center gap-2">
            <ManaBar currentMana={enemyMonster.currentMana} maxMana={enemyMonster.maxMana} isEnemy={true} />
          </div>
          <div className="mt-2">
            <MonsterSprite monster={enemyMonster} />
          </div>
        </div>

        {/* Battle log */}
        <div className="flex-grow flex items-center justify-center">
          <BattleLog messages={battleState.battleLog} />
        </div>

        {/* Player monster area */}
        <div className="flex flex-col items-start mt-4">
          <div className="mt-2">
            <MonsterSprite monster={playerMonster} />
          </div>
          <div className="flex items-center gap-2 mt-2">
            <span className="text-white font-pixel">{playerMonster.name}</span>
            <HealthBar
              currentHealth={playerMonster.currentHealth}
              maxHealth={playerMonster.maxHealth}
              isEnemy={false}
            />
          </div>
          <div className="flex items-center gap-2">
            <ManaBar currentMana={playerMonster.currentMana} maxMana={playerMonster.maxMana} isEnemy={false} />
          </div>
        </div>

        {/* Action panel */}
        <ActionPanel
          actions={actions}
          onAction={handleAction}
          disabled={battleState.currentTurn !== "player" || battleState.isAnimating}
        />
      </div>
    </div>
  )
}

