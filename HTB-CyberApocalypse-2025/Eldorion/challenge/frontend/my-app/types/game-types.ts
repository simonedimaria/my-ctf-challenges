export type MonsterState = "idle" | "attacking" | "defending" | "hit"

export interface Monster {
  name: string
  maxHealth: number
  currentHealth: number
  maxMana: number
  currentMana: number
  sprite: string
  state: MonsterState
}

export interface Action {
  name: string
  icon: string
  manaCost: number
  damage: number
}

export interface BattleState {
  currentTurn: "player" | "enemy"
  battleLog: string[]
  isAnimating: boolean
}

