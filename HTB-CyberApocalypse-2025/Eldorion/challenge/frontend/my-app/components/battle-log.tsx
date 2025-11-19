interface BattleLogProps {
  messages: string[]
}

export default function BattleLog({ messages }: BattleLogProps) {
  return (
    <div className="bg-[#2d1b2e] border-2 border-[#5d275d] rounded p-2 w-full max-h-24 overflow-y-auto">
      <ul className="text-white font-pixel space-y-2">
        {messages.slice(0, 3).map((message, index) => (
          <li key={index} className="leading-tight">
            {message}
          </li>
        ))}
      </ul>
    </div>
  )
}

