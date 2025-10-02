<?php

namespace WPRTWAF\Http;

class PreFilterDecision
{
    public function __construct(
        public readonly string $decision,
        public readonly string $reason
    ) {
    }
}
