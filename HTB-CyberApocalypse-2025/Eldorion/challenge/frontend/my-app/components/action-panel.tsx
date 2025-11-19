"use client"

import type { Action } from "@/types/game-types"

interface ActionPanelProps {
  actions: Action[]
  onAction: (action: Action) => void
  disabled: boolean
}

export default function ActionPanel({ actions, onAction, disabled }: ActionPanelProps) {
  return (
    <div className="bg-[#2d1b2e] border-t-4 border-[#5d275d] p-3 mt-2">
      <div className="grid grid-cols-4 gap-2">
        {actions.map((action, index) => (
          <button
            key={index}
            onClick={() => onAction(action)}
            disabled={disabled}
            className={`
              flex flex-col items-center justify-center p-2 
              bg-[#45283c] hover:bg-[#6e3852] 
              border-2 border-[#8f563b] rounded 
              transition-colors duration-150
              ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}
            `}
          >
            <span className="text-2xl mb-1">{action.icon}</span>
            <span className="text-white font-pixel">{action.name}</span>
            {action.manaCost > 0 && <span className="text-blue-300 font-pixel mt-1">MP: {action.manaCost}</span>}
          </button>
        ))}
      </div>
    </div>
  )
}

