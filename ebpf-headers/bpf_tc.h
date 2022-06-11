#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7
#define TC_ACT_TRAP                          \
  8 /* For hw path, this means "trap to cpu" \
     * and don't further process the frame   \
     * in hardware. For sw path, this is     \
     * equivalent of TC_ACT_STOLEN - drop    \
     * the skb and act like everything       \
     * is alright.                           \
     */
#define TC_ACT_VALUE_MAX TC_ACT_TRAP