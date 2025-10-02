<?php

namespace WPRTWAF\Actions;

use WPRTWAF\Http\NormalizedRequest;
use WPRTWAF\Http\PreFilterDecision;
use WPRTWAF\Rules\RuleMatch;

class DecisionEngine
{
    /**
     * @var \Closure
     */
    private readonly \Closure $optionsProvider;

    /**
     * @param callable(): array<string, mixed> $optionsProvider
     */
    public function __construct(callable $optionsProvider)
    {
        $this->optionsProvider = \Closure::fromCallable($optionsProvider);
    }

    public function decide(NormalizedRequest $request, ?PreFilterDecision $prefilter, ?RuleMatch $match): DecisionResult
    {
        $mode = $this->getMode();

        if ($prefilter !== null) {
            return $this->applyModeToPrefilter($prefilter, $mode);
        }

        if ($match === null) {
            return new DecisionResult($mode === Decision::MONITOR ? Decision::MONITOR : Decision::ALLOW, null, 'no_match');
        }

        $ruleDecision = $this->normalizeDecision($match->getRule()['action'] ?? Decision::BLOCK);

        return $this->applyModeToRule($ruleDecision, $match, $mode);
    }

    public function apply(DecisionResult $result): void
    {
        // Phase 2 focuses on computing the decision. Future phases will implement enforcement and logging.
    }

    private function getMode(): string
    {
        $options = ($this->optionsProvider)();
        $mode = $options['mode'] ?? Decision::MONITOR;

        return $this->normalizeDecision($mode);
    }

    private function applyModeToPrefilter(PreFilterDecision $prefilter, string $mode): DecisionResult
    {
        if ($prefilter->decision === Decision::ALLOW) {
            return new DecisionResult(Decision::ALLOW, null, $prefilter->reason);
        }

        if ($mode === Decision::MONITOR) {
            return new DecisionResult(Decision::MONITOR, null, $prefilter->reason);
        }

        if ($mode === Decision::CHALLENGE) {
            return new DecisionResult(Decision::CHALLENGE, null, $prefilter->reason);
        }

        return new DecisionResult(Decision::BLOCK, null, $prefilter->reason);
    }

    private function applyModeToRule(string $ruleDecision, RuleMatch $match, string $mode): DecisionResult
    {
        $reason = 'rule:' . ($match->getRule()['id'] ?? 'unknown');

        if ($mode === Decision::MONITOR) {
            return new DecisionResult(Decision::MONITOR, $match, $reason);
        }

        if ($mode === Decision::CHALLENGE) {
            return match ($ruleDecision) {
                Decision::ALLOW => new DecisionResult(Decision::ALLOW, $match, $reason),
                Decision::MONITOR => new DecisionResult(Decision::MONITOR, $match, $reason),
                default => new DecisionResult(Decision::CHALLENGE, $match, $reason),
            };
        }

        return match ($ruleDecision) {
            Decision::ALLOW => new DecisionResult(Decision::ALLOW, $match, $reason),
            Decision::MONITOR => new DecisionResult(Decision::MONITOR, $match, $reason),
            Decision::CHALLENGE => new DecisionResult(Decision::CHALLENGE, $match, $reason),
            default => new DecisionResult(Decision::BLOCK, $match, $reason),
        };
    }

    private function normalizeDecision(mixed $decision): string
    {
        $decision = is_string($decision) ? strtolower($decision) : Decision::MONITOR;

        return match ($decision) {
            Decision::ALLOW, Decision::MONITOR, Decision::BLOCK, Decision::CHALLENGE => $decision,
            default => Decision::MONITOR,
        };
    }
}
