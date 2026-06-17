package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	fake := flag.Bool("fake", false, "force the scripted offline planner (no Gemini)")
	only := flag.String("scene", "", "run only scenes whose name contains this substring")
	flag.Parse()

	apiKey := ""
	if !*fake {
		apiKey = loadGeminiKey()
		if apiKey == "" {
			fmt.Println("no GEMINI_API_KEY / GOOGLE_API_KEY found (env or .env); falling back to the scripted offline planner")
		}
	}
	liveModel := ""
	if apiKey != "" {
		liveModel = (&geminiPlanner{}).modelName()
	}

	lab, err := startHubbleOps()
	if err != nil {
		fmt.Fprintf(os.Stderr, "start embedded hubbleops: %v\n", err)
		os.Exit(1)
	}
	defer lab.Close()

	budget := 80 // global Gemini call cap: a stress lab must not itself run away
	var outcomes []SceneOutcome
	for _, scene := range allScenes() {
		if *only != "" && !strings.Contains(strings.ToLower(scene.Name), strings.ToLower(*only)) {
			continue
		}
		fmt.Printf("\n--- %s ---\n", scene.Name)
		fmt.Printf("    %s\n", scene.Description)

		var p planner
		if apiKey != "" {
			p = newGeminiPlanner(apiKey, scene.System, scene.Tools, &budget)
		} else {
			script := scriptFor(scene.Name)
			if script == nil {
				outcomes = append(outcomes, SceneOutcome{Scene: scene, Skipped: "no offline script"})
				continue
			}
			p = newFakePlanner(script)
		}

		tr, err := runScene(context.Background(), lab, p, scene)
		if err != nil {
			outcomes = append(outcomes, SceneOutcome{Scene: scene, Transcript: tr, Skipped: fmt.Sprintf("error: %v", err)})
			fmt.Printf("    SKIPPED: %v\n", err)
			continue
		}
		achieved, detail := scene.Verdict(tr)
		printTranscript(tr)
		outcomes = append(outcomes, SceneOutcome{Scene: scene, Transcript: tr, Achieved: achieved, Detail: detail})
	}

	mismatches := printScoreboard(outcomes, lab, liveModel)
	if mismatches > 0 {
		os.Exit(1)
	}
}

func (g *geminiPlanner) modelName() string {
	if model := os.Getenv("GEMINI_MODEL"); model != "" {
		return model
	}
	if model := os.Getenv("HUBBLEOPS_LIVE_GEMINI_MODEL"); model != "" {
		return model
	}
	return defaultGeminiModel
}

// loadGeminiKey checks the environment first, then .env in the working
// directory and the repo root (same precedence as the live tests).
func loadGeminiKey() string {
	if key := firstNonEmpty(os.Getenv("GOOGLE_API_KEY"), os.Getenv("GEMINI_API_KEY")); key != "" {
		return key
	}
	for _, path := range []string{".env", "../.env"} {
		if key := keyFromDotEnv(path); key != "" {
			return key
		}
	}
	return ""
}

func keyFromDotEnv(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	vals := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			vals[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return firstNonEmpty(vals["GOOGLE_API_KEY"], vals["GEMINI_API_KEY"])
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
