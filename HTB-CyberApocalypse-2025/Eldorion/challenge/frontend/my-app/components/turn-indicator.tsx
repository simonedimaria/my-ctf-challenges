interface TurnIndicatorProps {
  currentTurn: "player" | "enemy"
}

export default function TurnIndicator({ currentTurn }: TurnIndicatorProps) {
  return (
    <div className="absolute top-2 left-1/2 transform -translate-x-1/2 z-20">
      <div
        className={`
        px-4 py-1 rounded-full text-white font-pixel
        ${currentTurn === "player" ? "bg-green-600" : "bg-red-600"}
        border-2 border-[#8f563b]
        animate-pulse
      `}
      >
        {currentTurn === "player" ? "YOUR TURN" : "ENEMY TURN"}
      </div>
    </div>
  )
}

