# Set up suggested fee recipient

The fee recipient is an Ethereum address that receives transaction fees from block production, separately from the proposer reward that accrues on the beacon chain.

The fee recipient is forwarded to the execution client during block production - each validator can have its own fee recipient set or a single recipient may be used.

!!! warning
    The execution client is not required to follow the fee recipient suggestion and may instead send the fees to a different address - only use execution clients you trust!

    If no fee recipient is set up, the transaction fees are sent to the zero address, effectively causing them to be lost.

## Setting the fee recipient

Nimbus supports setting fee recipient per validator, or using defaults in both the validator client and beacon node.

Per-validator fee recipients are set using the [keymanager API](./keymanager-api.md).

Any validator without a per-validator recipient set will fall back to the `--suggested-fee-recipient` option if configured. In order, it selects from the first available, for each validator, of:

1. the keymanager API per-validator suggested fee recipient
2. `--suggested-fee-recipient` in the validator client
3. `--suggested-fee-recipient` in the beacon node

For example, `nimbus_beacon_node --suggested-fee-recipient=0x70E47C843E0F6ab0991A3189c28F2957eb6d3842` suggests to the execution client that `0x70E47C843E0F6ab0991A3189c28F2957eb6d3842` might be the coinbase. If this Nimbus node has two validators, one of which has its own suggested fee recipient via the keymanager API and the other does not, the former would use its own per-validator suggested fee cipient while the latter would fall back to `0x70E47C843E0F6ab0991A3189c28F2957eb6d3842`.


## Command line

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh --suggested-fee-recipient=0x70E47C843E0F6ab0991A3189c28F2957eb6d3842
    ```

=== "Prater"
    ```sh
    ./run-prater-beacon-node.sh --suggested-fee-recipient=0x70E47C843E0F6ab0991A3189c28F2957eb6d3842
    ```

=== "Validator Client"
    ```sh
    ./nimbus_validator_client --suggested-fee-recipient=0x70E47C843E0F6ab0991A3189c28F2957eb6d3842
    ```

## Logs

The configured fee recipient for every validator is logged at startup:

```
NOT 2022-11-10 08:27:02.530+01:00 Local validator attached ...
    initial_fee_recipient=70E47C843E0F6ab0991A3189c28F2957eb6d3842
```
