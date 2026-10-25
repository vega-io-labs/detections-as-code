<!-- Vega Detections PR -->

## What's changing?
<!-- One sentence: new detection / new skill / new memory / edit / retire / refactor. -->

## Files affected
<!-- List the detections/, skills/ and memories/ paths. -->

## Does this delete or retire any detection?
<!-- yes/no. If yes, list the YAMLs being removed and confirm the intent:
     delete (the id is reserved permanently) versus disable (state: disabled,
     which retains the id reservation). Deleting a SKILL.md deletes the skill;
     remove its id from every detection's skillIds in the same PR. For memories, deleting the file
     deletes the memory and renaming a title replaces it. -->

## Tested locally
<!-- Recommended before merge.
     Dry-run:
       python -m scripts.sync --tenant-url https://app.vega.io --detections-dir ./detections --skills-dir ./skills --memories-dir ./memories --dry-run
-->

## Notes for the reviewer
<!-- Items worth flagging: severity choice, query exclusions, data source dependencies, lookup tables referenced. -->

