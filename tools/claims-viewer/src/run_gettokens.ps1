# 1. First sign-in, save the tokens
python b2c_gettokens.py --policy SIGNINADPTIVE  --env nprd --save-tokens run1

# 2. Later, refresh and diff against the original id_token
python b2c_gettokens.py --policy SIGNINADPTIVE --env nprd --refresh-token-file run1_refresh.txt --compare-id-token run1_id.txt