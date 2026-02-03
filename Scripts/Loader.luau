
local function load(script)
    return loadstring(game:HttpGet(script))()
end

if game.PlaceId == 3804735158 then -- Princess Tycoon
    load("https://raw.githubusercontent.com/VoidShell-null/VoidShell-Hub/refs/heads/main/Scripts/The%20Tycoon%20Squad.luau")
    elseif game.PlaceId == 9791603388 then -- Underground war 2.0
    load("https://raw.githubusercontent.com/VoidShell-null/VoidShell-Hub/refs/heads/main/Scripts/SwordFightAura.luau")
    elseif game.PlaceId == 119564951960102 then -- Pass or die
    load("https://raw.githubusercontent.com/VoidShell-null/VoidShell-Hub/refs/heads/main/Scripts/Pass_or_DIe.lua")
    elseif game.PlaceId == 123741668193208 then -- 1m jump rope
    load("https://gist.githubusercontent.com/Bwhw827g29wh/84e8ba08f520682a4de508c19121ec34/raw/4e34921858e5fc5af1999e7650cb85d3db6d2f29/The%2520$1M%2520Jump%2520Rope.txt")
    elseif game.PlaceId == 6104994594 then -- Pilfering Pirate
    load("https://raw.githubusercontent.com/Bwhw827g29wh/Scripts/refs/heads/main/Pilfering%20Pirate.lua")
end

