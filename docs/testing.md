# Testing

The testing strategy in this project focuses on thorough unit tests for the core (`bcr-ebill-core`)
functionality components such as the bill validation, persistence (`bcr-ebill-persistence`)
and transport (`bcr-ebill-transport`) logic and basic integration tests on the api (`bcr-ebill-api`)
layer that integrates these parts and very basic wiring tests on the outer SDK layers (`bcr-ebill-wasm`).
