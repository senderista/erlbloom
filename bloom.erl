% bloom filter in erlang
% formulae from http://en.wikipedia.org/wiki/Bloom_filter

-module(bloom).
%% Public interface
-export([init/2, add/2, exists/2, get_bits/1]).
%% Private functions
-export([loop/4]).

%% @doc Starts the server process and returns the server pid.
%% @end
-spec init(integer(),float()) -> pid().
init(MaxElements, MaxFalsePos) ->
    % assert 0 < MaxFalsePos < 1
    % The required number of bits m, given n (the number of inserted elements)
    % and a desired false positive probability p
    % (and assuming the optimal value of k is used) is
    % m = -(n*ln(p))/(ln(2)^2)
    BitArrayLen = round(-((MaxElements * math:log(MaxFalsePos)) / (math:pow(math:log(2), 2)))),
    % For a given m and n, the value of k (the number of hash functions)
    % that minimizes the probability is
    % k = (m/n)*ln(2)
    NumHashFuncs = round((BitArrayLen / MaxElements) * math:log(2)),
    Pid = spawn(?MODULE, loop, [fun crypto:md5/1, 128, NumHashFuncs, <<0:BitArrayLen>>]),
    Pid.

%% @doc Tail-recursive message handler for the server process.
%% @end
%% @private
-spec loop(fun((binary()) -> binary()),integer(),integer(),binary()) -> 'true'.
loop(BaseHashFunc, BaseHashLen, NumHashFuncs, BitArray) ->
    BitArrayLen = bit_size(BitArray),
    <<BitArrayVal:BitArrayLen>> = BitArray,
    SubHashLen = BaseHashLen div NumHashFuncs,
    receive
        {From, {exists, Id, Key}} ->
            true = math:pow(2, SubHashLen) >= BitArrayLen,
            <<BaseHash:BaseHashLen>> = BaseHashFunc(Key),
            SubHashes = lists:sublist([(SubHash rem BitArrayLen) || <<SubHash:SubHashLen>> <= <<BaseHash:BaseHashLen>>], NumHashFuncs),
            SubHashesMask = lists:foldl(fun(Elem, Acc) -> (1 bsl Elem) bor Acc end, 0, SubHashes),
            <<BitArrayVal:BitArrayLen>> = BitArray,
            case (BitArrayVal band SubHashesMask) of
                SubHashesMask -> From ! {ok, Id};
                _ ->  From ! {{error, not_found}, Id}
            end,
            loop(BaseHashFunc, BaseHashLen, NumHashFuncs, BitArray);
        {From, {add, Id, Key}} ->
            true = math:pow(2, SubHashLen) >= BitArrayLen,
            <<BaseHash:BaseHashLen>> = BaseHashFunc(Key),
            SubHashes = lists:sublist([(SubHash rem BitArrayLen) || <<SubHash:SubHashLen>> <= <<BaseHash:BaseHashLen>>], NumHashFuncs),
            NewBitArrayVal = lists:foldl(fun(Elem, Acc) -> (1 bsl Elem) bor Acc end, BitArrayVal, SubHashes),
            From ! {ok, Id},
            loop(BaseHashFunc, BaseHashLen, NumHashFuncs, <<NewBitArrayVal:BitArrayLen>>);
        {From, {get_bits, Id}} ->
            From ! {ok, Id, BitArray},
            loop(BaseHashFunc, BaseHashLen, NumHashFuncs, BitArray);
        stop ->
            true
    end.

%% @doc Adds Key to the filter maintained by the server Pid.
%% @end
-spec add(pid(),binary()) -> any().
add(Pid, Key) ->
    Id = make_ref(),
    Pid ! {self(), {add, Id, Key}},
    receive
        {Status, Id} ->
            Status
    end.

%% @doc Tests the filter maintained by the server Pid for existence of Key.
%% @end
-spec exists(pid(),binary()) -> any().
exists(Pid, Key) ->
    Id = make_ref(),
    Pid ! {self(), {exists, Id, Key}},
    receive
        {Status, Id} ->
            Status
    end.

%% @doc Gets the bitstring implementing the filter maintained by the server Pid (for debugging only).
%% @end
-spec get_bits(pid()) -> binary().
get_bits(Pid) ->
    Id = make_ref(),
    Pid ! {self(), {get_bits, Id}},
    receive
        {Status, Id, Bits} ->
            Bits
    end.
