package internal

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/spf13/viper"
)

type Rule struct {
	Name       string `json:"name",mapstructure:"name"`
	Expression string `json:"expression",mapstructure:"expression"`
	Enabled    bool   `json:"enabled",mapstructure:"enabled"`
}
type CompiledRule struct {
	Program    *vm.Program
	Name       string
	Expression string
	Enabled    bool
}

type RuleEvaluator struct {
	Rules []CompiledRule
	mu    sync.RWMutex
	v     *viper.Viper
}

func NewRuleEvaluator() (*RuleEvaluator, error) {
	v := viper.New()
	v.SetConfigFile("rulenames.yaml")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

	engine := &RuleEvaluator{
		Rules: make([]CompiledRule, 0),
		v:     v,
	}
	if err := v.ReadInConfig(); err != nil {
		return engine, nil
	}
	var config struct {
		Rules []Rule `mapstructure:"rules"`
	}
	if err := v.Unmarshal(&config); err != nil {
		return engine, nil
	}
	for _, rule := range config.Rules {
		if !rule.Enabled {
			continue
		}
		program, err := expr.Compile(rule.Expression, expr.Env(AggregatedFlow{}))
		if err != nil {
			return nil, fmt.Errorf("error compiling rule %s: %w", rule.Name, err)
		}
		engine.Rules = append(engine.Rules, CompiledRule{
			Name:       rule.Name,
			Program:    program,
			Enabled:    rule.Enabled,
			Expression: rule.Expression,
		})
	}
	return engine, nil
}

type CandidateFlow struct {
	Flow     AggregatedFlow
	RuleName string
}

func (re *RuleEvaluator) Evaluate(items []*AggregatedFlow) ([]CandidateFlow, error) {
	workers := runtime.NumCPU()
	resultsChan := make(chan CandidateFlow, len(items)*len(re.Rules))
	jobs := make(chan int, len(items))
	var wg sync.WaitGroup

	re.mu.RLock()
	defer re.mu.RUnlock()

	for range workers {
		wg.Go(func() {
			for idx := range jobs {
				item := items[idx]

				for i := range re.Rules {
					result, err := vm.Run(re.Rules[i].Program, item)
					if err != nil {
						continue
					}
					if matched, ok := result.(bool); ok && matched {
						resultsChan <- CandidateFlow{
							Flow:     *item,
							RuleName: re.Rules[i].Name,
						}
					}
				}
			}
		})
	}

	for i := range items {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(resultsChan)

	results := make([]CandidateFlow, 0, len(resultsChan))
	for r := range resultsChan {
		results = append(results, r)
	}
	return results, nil
}
