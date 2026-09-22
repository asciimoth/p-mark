# tombstone_churn

Checks the high-churn regression for the 32,768-entry process map.

Assertions:

- more than 32,768 unknown process exits do not create tombstones;
- a matching process started after the churn still gets its socket fwmark;
- cleanup triggered by unrelated exits does not replace a live marked process
  with a tombstone.

