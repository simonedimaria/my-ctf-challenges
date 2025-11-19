import time
import os
import argparse
from typing import List, Tuple
from logging import Logger
from web3 import Web3
from web3.contract import Contract
from .EVMBot import EVMBot as Bot
from .utils import is_node_running, setup_logger, load_env, get_contracts_instances, get_bots

FLAG = os.getenv("FLAG", "HTB{h3ll0_ch41n_sc0ut3r}") 
USERS_PODS = {
    1: [ # weird food recipes
        "**Canned Bean and Hot Sauce Granola**: 1 can of black beans, drained and rinsed, 2 cups rolled oats, 1/2 cup honey or maple syrup, 1/4 cup vegetable oil, 2 tablespoons hot sauce, 1 teaspoon smoked paprika, 1/2 teaspoon salt, 1/4 cup dried cranberries or raisins (optional). Preparation: 1) Preheat the oven to 325°F (165°C) and line a baking sheet with parchment paper. 2) In a large mixing bowl, combine the rolled oats and drained black beans, ensuring the beans are roughly mashed but still intact for texture. 3) In a saucepan, gently heat the honey or maple syrup with the vegetable oil until well combined. 4) Stir in the hot sauce, smoked paprika, and salt into the syrup mixture. 5) Pour the liquid mixture over the oat and bean mixture, stirring thoroughly to ensure even coating. 6) Spread the mixture evenly onto the prepared baking sheet. 7) Bake for 25-30 minutes, stirring halfway through to prevent burning and ensure even toasting. 8) Remove from the oven and allow to cool completely. 9) Once cooled, mix in dried cranberries or raisins if available. 10) Break into clusters and store in airtight containers. Description: Venture into the bold and spicy world of our Canned Bean and Hot Sauce Granola, a daring blend that combines the hearty protein of black beans with the crunchy texture of rolled oats, all elevated by a fiery kick of hot sauce. This unconventional granola is a testament to survival ingenuity, utilizing long-lasting canned beans and oats that provide essential nutrients and sustained energy in post-apocalyptic environments. The addition of hot sauce not only imparts a unique flavor profile but also stimulates appetite and provides a sense of comfort through its warmth. Dried cranberries or raisins, if available, add a touch of sweetness to balance the heat, creating a complex and satisfying snack. The granola's compact form makes it easy to store and transport, while its high protein and fiber content ensure that it supports physical endurance and mental clarity when traditional food sources are scarce. Ideal for boosting morale and providing essential sustenance, this granola is a versatile and resilient option for maintaining health and energy during prolonged survival situations.",
        "**Instant Ramen and Canned Pineapple Stir-Fry**: 2 packets of instant ramen (flavor packets discarded or repurposed), 1 can of pineapple chunks in juice, 1 can of mixed vegetables, 2 tablespoons of soy sauce or tamari, 1 tablespoon of vegetable oil, 1 teaspoon of chili flakes (optional), chopped nuts for garnish (optional). Preparation: 1) Drain the pineapple chunks and mixed vegetables, reserving the juice if desired for added flavor. 2) In a large skillet or wok, heat the vegetable oil over medium heat. 3) Add the mixed vegetables to the skillet and sauté for 3-4 minutes until they begin to soften. 4) Stir in the pineapple chunks, allowing them to caramelize slightly. 5) Pour in the soy sauce or tamari and sprinkle chili flakes if using, mixing thoroughly to combine the flavors. 6) Add the cooked instant ramen noodles to the skillet, tossing everything together until the noodles are evenly coated and heated through. 7) Remove from heat and garnish with chopped nuts for added crunch, if available. 8) Serve hot as a sweet and savory stir-fry that satisfies diverse taste buds. Description: Experience the bold and eclectic flavors of our Instant Ramen and Canned Pineapple Stir-Fry, a creative fusion that blends the comforting familiarity of instant noodles with the tropical sweetness of pineapple. This dish ingeniously utilizes long-lasting canned goods and instant noodles, which are essential for survival scenarios due to their extended shelf life and ease of preparation. The combination of mixed vegetables ensures a supply of necessary vitamins and minerals, while the soy sauce adds a savory depth that balances the sweetness of the pineapple. The optional chili flakes introduce a spicy kick to invigorate the palate, and the chopped nuts provide additional protein and texture. This stir-fry is both nutritionally balanced and flavorful, offering a satisfying meal that can be quickly assembled with minimal resources. Its versatility allows for ingredient substitutions based on available supplies, making it a reliable and adaptable option for sustaining energy and boosting morale in times of scarcity.",
        "**Canned Sardine and Chocolate Spread Delight**: 1 can of sardines in olive oil, 2 tablespoons of dark chocolate spread, 2 slices of sturdy bread (rye or multigrain), a sprinkle of crushed red pepper flakes (optional). Preparation: 1) Drain the sardines and gently mash them with a fork. 2) Spread a generous layer of dark chocolate spread on each slice of bread. 3) Evenly distribute the mashed sardines over one slice of bread. 4) Sprinkle crushed red pepper flakes for an extra kick, if desired. 5) Top with the second slice of bread, chocolate side down. 6) Press lightly, cut into manageable pieces, and serve. Description: Experience the bold and unexpected flavors of our Canned Sardine and Chocolate Spread Delight, a daring combination that challenges conventional palates. This intriguing fusion marries the savory richness of sardines with the smooth, bittersweet notes of dark chocolate spread, all nestled between hearty slices of multigrain bread. The robust protein from the sardines provides essential nutrients, while the chocolate adds a unique depth of flavor that elevates this unconventional sandwich to a gourmet survival meal. Excellent for post-apocalyptic scenarios, this recipe utilizes long-lasting canned goods and shelf-stable spreads, ensuring sustenance with minimal preservation needs. The high protein and calorie content offer vital energy and nourishment when traditional food sources are limited, making it a practical and innovative choice for enduring harsh conditions.",
        "**Peanut Butter and Pickle Sandwich**: 2 slices of bread (white, whole wheat, or sourdough), 2 tablespoons of Peanut Butter, 4-6 dill pickle slices, a dash of hot sauce, lettuce, or honey (optional). Preparation: 1) Apply peanut butter evenly on one side of each bread slice. 2) Layer the pickle slices on one peanut butter-covered bread slice. 3) Add a sprinkle of salt, hot sauce, or extra layers like lettuce. 4) Place the second bread slice on top, peanut butter side down. Press gently. 5) Cut diagonally for easier handling and enjoy. Description: Embark on an unexpected gastronomic journey with our Peanut Butter & Pickle Symphony, a harmonious fusion of contrasting flavors and textures that redefine the boundaries of contemporary cuisine. This avant-garde creation marries the rich, velvety notes of artisanal creamy peanut butter with the crisp, tangy zest of hand-selected dill pickles, meticulously layered between slices of freshly baked, stone-ground sourdough bread.",
    ],
    
    2: [ # humanity legendary video masterpieces
        "https://youtu.be/xuCn8ux2gbs",
        "https://youtu.be/W85F-UmnbF4"
        "https://youtu.be/JxS5E-kZc2s",
        "https://youtu.be/dQw4w9WgXcQ",
    ],
    
    3: [ # random facts
        "**Australia is Wider Than the Moon**: The continent of Australia extends approximately 4,000 kilometers from its easternmost to westernmost points. In comparison, Earth's Moon possesses a diameter of roughly 3,474 kilometers. This measurement indicates that Australia's longitudinal breadth exceeds the lunar diameter by approximately 526 kilometers. Such a comparison highlights the substantial scale of the Australian landmass relative to the Moon, underscoring the vastness of continental dimensions in relation to celestial bodies.",
        "**Humans Share 50% of Their DNA with Bananas**: Human beings (Homo sapiens) share approximately 50% of their genetic material with bananas (Musa acuminata). This genomic homology reflects the fundamental biological processes and genetic sequences that are conserved across diverse species due to shared evolutionary ancestry. The overlapping genetic information encompasses genes responsible for basic cellular functions, such as cellular respiration, DNA replication, and protein synthesis. This similarity underscores the interconnectedness of life on Earth and the common molecular mechanisms that underpin various forms of life, despite the significant phenotypic differences between humans and banana plants.",
        "**The Great Emu War**: The Emu War was a nuisance wildlife management military operation undertaken in Australia over the later part of 1932 to address public concern over the number of emus, a large flightless bird indigenous to Australia, said to be destroying crops in the Campion district within the Wheatbelt of Western Australia. The unsuccessful attempts to curb the emu population employed Royal Australian Artillery soldiers armed with Lewis guns—leading the media to adopt the name 'Emu War' when referring to the incident. Although many birds were killed, the emu population persisted and continued to cause crop destruction. ",
        "**A Tardigrade Can Survive in Space**: Tardigrades, also known as water bears, are microscopic invertebrates renowned for their ability to withstand extreme conditions, including the vacuum and radiation of outer space. This resilience is primarily due to their capacity to enter a desiccated state called cryptobiosis, where their metabolic activities nearly cease, allowing them to survive prolonged periods without water and endure harsh environments."
    ],
    
    4: [ # gen-z memes 101 history
        "The Skibidi Toilet meme is a surreal, animated internet phenomenon that originated on social media platforms, particularly TikTok and YouTube, around 2023. The series features a bizarre and chaotic narrative involving disembodied human heads emerging from toilets, singing or yelling the word 'Skibidi' in sync with a fast-paced, techno-style track. These 'toilet heads' are often in conflict with humanoid characters whose heads are replaced with cameras, TVs, or other electronic devices.",
        "The Ligma meme is a classic example of bait-and-switch humor that emerged around 2018. It gained popularity as a crude internet joke, primarily on platforms like Reddit, Instagram, and Twitter. It relies on wordplay to trick an unsuspecting person into asking for clarification, only to be met with a humorous or inappropriate punchline.",
        "The Ohio meme, that gained traction in the early 2020s, is a tongue-in-cheek internet joke that depicts the U.S. state of Ohio as a strange, dystopian, or otherworldly place where bizarre and impossible things happen. While Ohio is an ordinary Midwestern state in reality, internet culture has turned it into a symbol of absurdity and chaos.",
        "The Amogus meme is a surreal and simplified spin-off of the online multiplayer game Among Us, developed by InnerSloth. This game, released in 2018, involves players taking on the roles of Crewmates and Impostors in a spaceship setting. The game's popularity skyrocketed in 2020 during the COVID-19 pandemic, and it spawned countless memes. The Amogus meme is one of the strangest and most iconic. The word 'Amogus' is a humorous corruption of the game's title, Among Us. This distortion likely arose from casual or rushed pronunciations of the name. The meme often pairs the game's simplistic Crewmate characters (bean-shaped astronauts) with exaggerated humor or absurd captions."
    ],
    
    5: [ # blockchain 101 history
        "**Bitcoin and the Genesis Block (2009)**: In January 2009, the enigmatic creator Satoshi Nakamoto mined the first block of the Bitcoin blockchain, known as the Genesis Block. This pivotal event marked the birth of blockchain technology, introducing a decentralized ledger system that enabled peer-to-peer transactions without the need for intermediaries. The Genesis Block contained a hidden message referencing a headline about bank bailouts, symbolizing Bitcoin's intent to offer an alternative to traditional financial systems.",
        "**Ethereum and the Introduction of Smart Contracts (2015)**: Launched in July 2015 by Vitalik Buterin and his team, Ethereum expanded the capabilities of blockchain technology beyond simple transactions. By introducing smart contracts—self-executing contracts with the terms directly written into code—Ethereum enabled developers to build decentralized applications (dApps) and decentralized finance (DeFi) platforms. This innovation paved the way for a new wave of blockchain use cases, including decentralized organizations, gaming, and more complex financial instruments.",
        "**The DAO Hack and the Birth of Ethereum Classic (2016)**: In June 2016, The DAO, a decentralized autonomous organization built on Ethereum, was exploited due to a vulnerability in its smart contract code, resulting in the theft of approximately $50 million worth of Ether. In response, the Ethereum community decided to implement a hard fork to reverse the hack and return the stolen funds, leading to the creation of two separate blockchains: Ethereum (ETH) and Ethereum Classic (ETC). This incident highlighted the challenges of governance and security in decentralized systems and underscored the importance of robust smart contract auditing.",
        "**Bitcoin's 100k Milestone (2024)**: On December 4, 2024, Bitcoin surpassed the $100,000 mark for the first time in its history. This significant milestone was driven by increased institutional adoption, the approval of Bitcoin exchange-traded funds (ETFs) in the U.S., and a favorable regulatory environment under President Donald Trump's administration. The surge in Bitcoin's value reflects its growing acceptance as a mainstream financial asset and a hedge against traditional market fluctuations. The year 2024 also witnessed unprecedented growth in cryptocurrency adoption worldwide. The number of cryptocurrency owners reached 562 million, marking a 34% increase from the previous year and representing approximately 6.8% of the global population.",
    ]
}

def start_simulation(w3: Web3, bots: List[Tuple[str, str]], contracts: List[Contract], rpc_url: str,
                     max_retries: int, retry_interval: int, logger: Logger):
    logger.info(f"\nStarting simulation with {len(bots)} bots.")

    for contract_name, contract_instance in contracts.items():
        if contract_name == "CryoPod":
            CryoPod = contract_instance

    for n in range(1, 5):
        for bot_id, bot_info in enumerate(bots, 1):
            logger.info(f"Starting bot-{bot_id} with info {bot_info}.")
            bot_addr, bot_pvk = bot_info
            if (n * bot_id) == 15:
                secret = FLAG
            else: 
                secret = USERS_PODS.get(bot_id).pop()
            Bot(
                bot_id=bot_id, bot_addr=bot_addr,
                w3=w3, target_contract=CryoPod, function_sig="storePod(string)", args=[secret], tx_options={},
                private_key=bot_pvk, rpc_url=rpc_url,
                max_retries=max_retries, retry_interval=retry_interval, logger=logger
            ).start()
            time.sleep(5)
        logger.info("Simulation ended.")

def main():
    env = load_env()
    logger = setup_logger(env["BOT_LOG_FILE"])
    while not is_node_running():
        logger.info("Waiting for node to start...")
        time.sleep(10)
    w3 = Web3(Web3.HTTPProvider(env["LOCAL_RPC_URL"]))
    contract_address_mapping = {"Setup": "setupAddress", "CryoPod": "targetAddress"}
    contracts = get_contracts_instances(w3, "/home/ctf/backend/contracts/compiled", contract_address_mapping, logger)
    bots = get_bots()
    start_simulation(
        w3=w3,
        bots=bots,
        contracts=contracts,
        rpc_url=env["LOCAL_RPC_URL"],
        max_retries=env["BOT_MAX_RETRIES"],
        retry_interval=env["BOT_RETRY_INTERVAL"],
        logger=logger
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    _ = parser.parse_args()
    main()
