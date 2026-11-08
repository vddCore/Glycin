## Glycin
Glycin is a decryption data extractor employing simple heuristics and static analysis
to help automate the recovery of global-metadata.dat for CarX Street.

Uses the excellent PeNet, ELFSharp and Iced libraries to facilitate all the tasks required
to recover the data.

## Usage
`./glycin /path/to/carx-street/GameAssembly.(dll|so)`

## Warning
At the time of writing only Windows and Linux native versions of the game are supported.
