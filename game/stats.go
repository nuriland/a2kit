package game

import "strconv"

// Stats is a character's stat table, once at login with every row, and then with the rows that changed (buffs).
// A percentage is in hundredths, a stat at 0 has no row, and the sheet's totals like Attack and Defense are not rows,
// they seem to be calculated by the client.
type Stats struct {
	Entity Entity // 0 on the full table, which is only visible to the player
	Full   bool   // if the table is the full one (player opened the stat sheet, vs. updated stats by buffs)
	Rows   map[Stat]int32
}

// Stat is a row's id in the stat table
type Stat uint16

func (s Stat) String() string {
	if n, ok := statNames[s]; ok {
		return n
	}
	return strconv.Itoa(int(s))
}

var statNames = func() map[Stat]string {
	m := map[Stat]string{
		// the main page
		1:   "might",
		3:   "intelligence",
		4:   "constitution",
		133: "critical_hit_resist",
		193: "base_hp",
		205: "move_speed",
		242: "stamina",
		282: "combat_speed",

		// combat
		32:  "weapon_damage_boost",
		38:  "critical_attack",
		41:  "critical_damage_defense",
		69:  "power_shard_damage",
		70:  "damage_tolerance",
		98:  "back_attack",
		99:  "back_defense",
		100: "back_attack_critical",
		284: "penetration",
		587: "front_attack",
		588: "front_defense",
		589: "front_attack_damage_boost",
		591: "front_attack_critical",
		592: "front_attack_critical_resist",

		// hit detection
		146: "multi_hit_chance",
		147: "multi_hit_resist",
		255: "block",
		442: "perfect_chance",
		443: "double_chance",
		444: "regeneration",
		445: "endurance",
		446: "perfect_resist",
		447: "double_resist",
		448: "regeneration_penetration",
		449: "endurance_penetration",

		// status effects, a base for every effect and a bonus per group of them
		158: "status_chance",
		159: "status_resist",
		321: "stun_chance",
		322: "stun_resist",
		325: "fear_chance",
		326: "fear_resist",
		329: "frost_chance",
		330: "frost_resist",

		// pvp, pve, and boss
		50:  "boss_attack",
		51:  "boss_defense",
		56:  "pve_attack",
		57:  "pve_defense",
		60:  "pvp_attack",
		61:  "pvp_defense",
		65:  "pvp_damage_boost",
		76:  "pvp_damage_tolerance",
		110: "pve_accuracy",
		122: "pve_evasion",
		125: "pvp_evasion",
		379: "pve_damage_boost",
		380: "pve_damage_tolerance",
		569: "pvp_block",

		// special and resources
		208: "mount_ground_movement",
		210: "mount_sprint_stamina",
		214: "flight_speed",
		220: "hp_potion_recovery_pct",
		221: "hp_potion_recovery", // likely, next to its percentage
		298: "flight_power",       // shown divided by 100, and the max of the flight gauge
		385: "cooldown",           // @REVIEW: there's more stats to cover since the client displayed sheet adds extra % from elsewhere
		386: "mp_cost",
	}
	for i, g := range []string{"cogni", "fera", "natura", "varian"} {
		for j, s := range []string{"attack", "defense", "accuracy", "evasion", "critical_hit", "critical_hit_resist", "block_penetration", "block"} {
			m[Stat(393+8*i+j)] = g + "_" + s // the genus page, 8 rows a genus
		}
	}
	return m
}()

type GearScore struct {
	Now  uint32
	Best uint32 // the highest so far (sent even when gear is downgraded)
}

type CombatPower struct {
	Now  uint64
	Best uint64 // the highest so far (sent even when gear is downgraded)
}

func (GearScore) event()   {}
func (CombatPower) event() {}
