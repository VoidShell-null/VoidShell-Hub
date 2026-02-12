# VoidShell InstanceToLua v1.3

Tool to turn Roblox Instances into Lua code. supports decompiling and smart property filtering ( not tested in all instances ).

---

### 📜 Info

**LICENSE:** *MIT*

Instance To Lua By `@nullspecter.` ( Discord User )

*Version*: 1.3

*Tool Name*: VoidShell InstanceToLua

*Tool Public release*: Feb 12, 2026

 First File Generated was on August 2nd, 2025, at 7:02 PM. As a Private Tool:
https://pastebin.com/aSWk16AP

Day created: ~~forgotten~~

---

### ✅ Executor Support
Relies on `getproperties`. If your executor doesn't have it, this won't work.

* **Works on:** Valex, RonixExploit, Krnl, Frostware, Volcano, JJsploit, Xeno, Volt, Zenith, Delta, Fluxus.

* **Probably Won't Work:** Solara, Wave, Macsploit, Codex, Seliware, Evon, Hydrogen, Synapse X, Arceus X, VegaX, Ronix, Swift, Velocity, Bunni, Potassium, Nucleus.


##### - (Old Env check Dec 2025 - 7 Jan 2026)
#### - *env inspection was old and may varies.*
---

### 🔥 Features
* **Decompiling:** Works for LocalScripts and ModuleScripts ( executor must have `decompile` func ) .

* **Clean Output:** Ignores properties that aren't modified.

* **Modern Support:** Handles Attributes, Tags, gethui, and LocalPlayer.

* **Space Handling:** Supports Characters/Folders with spaces in the name.

* **Caching:** Fast repeat conversions.

---

### 🛠️ Documentation 

## initialize
```luau
local InstanceToLuaModule = loadstring(game:HttpGet("https://raw.githubusercontent.com/VoidShell-null/VoidShell-Hub/refs/heads/main/Utils/InstanceToLua.lua"))()
local converter = InstanceToLuaModule.new()
```

## determine if the Executor is Supported
```luau
if not converter and messages then
    for _, msg in ipairs(messages) do
        local formatted = string.format("  [%s] %s: %s", msg.timestamp, msg.type, msg.message)
        print(formatted)
    end
    return
end
```
## **Conversion methods**
- Save to file
```luau
converter:toFile(game.Lighting, mode: string [Reusable, Tables], "hi.lua") -- converter will auto name the file if not provided
```

- Copy to clipboard
```luau
converter:toClipboard(instance, mode: string [Reusable, Tables])
```

- Code string only
```luau
--// Returns the code string
local result = converter:convertCached(instance, mode: string [Reusable, Tables]) -- caching

local result = converter:convert(instance, mode: string [Reusable, Tables]) -- no caching
```

- Use the global function
```luau
--// use the global
InstanceToLua(converter, instance, mode, type: string [clipboard, file], filename)

--// returns the code string
local result = InstanceToLua(converter, instance, mode: string [Reusable, Tables])
```

## **messages - status**

```luau
--// Default to warn(formatted)
function InstanceToLuaModule:callback(formatted, message, type)
    YourTextLabel.Text = YourTextLabel.Text.."\n"..formatted
    warn("Status: ", type)
    warn("message: ", message)
    warn("formatted: ", formatted) --// [20:7:9]: SUCCESS: message
    return 
end
```
- add message
```luau
--// _addMessage
converter:_addMessage(type: string [SUCCESS, INFO, ERROR, WARNING, Any], message: string)
```
- Get all messages
```luau
--// get all messages
for _, msg in ipairs(converter:getMessages()) do
    local formatted = string.format("  [%s] %s: %s", msg.timestamp, msg.type, msg.message)
    print(formatted)
end
```

- Get last status
```luau
converter:getStatus(): string
```

- Get last message
```luau
converter:getLastMessage(): table {type: string, timestamp: string, message: string}
```

- Get last result
```luau
converter:getResult(): string
```

- Clear messages
```luau
converter:clearMessages(): ()
```

- Cached numbers
```luau
--// how many caches - note that it's auto cleaned when it reach 27
converter:CacheLength(): number
```

- Convertion time
```luau
print( "Time taken: ", converter:getTimerString(): number )
```

```luau
local timer = converter:getTimer(): number
print("Elapsed seconds: " .. timer:getElapsed())
```

- Check cache
```luau
local cached = converter:getCached(instance)
if cached then
    print("Cached result exists from:", os.date("%H:%M:%S", cached.time))
    print("Status:", cached.status)
    -- cached.result : the code string
end
```

- use caching?, Default to false
```luau
converter.UseCache = true
```


- Streaming , u can see the code while getting generated through message, `function InstanceToLuaModule:callback(formatted, message, type)`
```luau
--// Streaming but will make conversion slightly longer, Default to false
converter.Stream = true
```

- Ignore unmodified properties
```luau
--// to ignore unmodified properties, Default to true
self.ignoreUnmodified = true 
```

- Comments
```luau
--// addComment, add the full instance name above it , Default to true
self.addComment = true
```

- decompile, Default to true
```luau
self._decompile = true
```


# Example usage and test
-- Game : Fencing | https://www.roblox.com/games/12109643/Fencing

```luau
do
local converter, messages = InstanceToLuaModule.new()

if not converter and messages then
    for _, msg in ipairs(messages) do
        local formatted = string.format("  [%s] %s: %s", msg.timestamp, msg.type, msg.message)
        print(formatted)
    end
    return 
end

local Foil = game.Players.LocalPlayer.Backpack.Foil
Foil:AddTag("VoidShell Hub")
Foil:SetAttribute("Null", "Nil")
Foil.Handle.FormFactor = "Custom"

converter.Stream = false
converter.ignoreUnmodified = true
converter.addComment = false
converter:toFile(Foil, "Reusable") -- game.Players.LocalPlayer.Backpack.Spray, "hi.lua") -- game.Players.LocalPlayer.PlayerGui.SprayGui)

task.wait(5)

print(converter:CacheLength())
-- Check cache directly
local cached = converter:getCached(workspace)
if cached then
    print("Cached result exists from:", os.date("%H:%M:%S", cached.time))
    print("Status:", cached.status)
end

print(converter:getStatus())

--// getLastMessage
print(converter:getLastMessage())

--// clearMessages
converter:clearMessages()

warn("All messages:")
print(converter:getTimerString())

for _, msg in ipairs(converter:getMessages()) do
    local formatted = string.format("  [%s] %s: %s", msg.timestamp, msg.type, msg.message)
    print(formatted)
end

local timer = converter:getTimer()
print("Elapsed seconds: " .. timer:getElapsed())

end
```


###  Default mode is `Reusable`
