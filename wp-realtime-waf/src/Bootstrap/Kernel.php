<?php

namespace WPRTWAF\Bootstrap;

use WPRTWAF\Actions\Decision;
use WPRTWAF\Actions\DecisionEngine;
use WPRTWAF\Actions\DecisionResult;
use WPRTWAF\Http\PreFilter;
use WPRTWAF\Http\RequestContextFactory;
use WPRTWAF\Http\RequestNormalizer;
use WPRTWAF\Rules\RuleEngine;
use WPRTWAF\Logging\EventLogger;

class Kernel
{
    public function __construct(
        private readonly RequestContextFactory $requestFactory,
        private readonly RequestNormalizer $normalizer,
        private readonly PreFilter $preFilter,
        private readonly RuleEngine $ruleEngine,
        private readonly DecisionEngine $decisionEngine,
        private readonly EventLogger $eventLogger
    ) {
    }

    public function handleRequest(): DecisionResult
    {
        $context = $this->requestFactory->fromGlobals();
        $request = $this->normalizer->normalize($context);

        $prefilterDecision = $this->preFilter->evaluate($request);
        $ruleMatch = null;

        if ($prefilterDecision === null || $prefilterDecision->decision !== Decision::ALLOW) {
            $ruleMatch = $this->ruleEngine->match($request);
        }

        $decision = $this->decisionEngine->decide($request, $prefilterDecision, $ruleMatch);
        $this->decisionEngine->apply($decision);
        $this->eventLogger->logDecision($request, $decision);

        return $decision;
    }
}
