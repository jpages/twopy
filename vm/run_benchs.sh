

# Number of times a benchmark is run
N=$1

printf "TWOPY\n"
for i in {0..N}
do
    for bench in ./benchmarks/*.py
    do
        # Get benchmark name from path
        NAME=$(basename $bench)
        NAME="${NAME%.*}"

        # Run twopy with options and grep using key
        OUT=$(/usr/bin/time -f "%e" ../../tests/cpython/python twopy.py $bench | grep real)

        # Split using ":" and take 2nd element (e.g. 120)
        RES="$(cut -d':' -f2 <<<"$OUT")"

        # Print "NAME:RES"
        printf "$NAME"
        printf ":$RES"
        printf "\n"
    done
    printf "\n"
done

printf "\nPYPY3\n"
for i in {0..N}
do
    for bench in ./benchmarks/*.py
    do
        # Get benchmark name from path
        NAME=$(basename $bench)
        NAME="${NAME%.*}"

        # Run twopy with options and grep using key (e.g. "Executed tests: 120")
        OUT=$(/usr/bin/time -f "%e" pypy3 $bench | grep real)

        # Split using ":" and take 2nd element (e.g. 120)
        RES="$(cut -d':' -f2 <<<"$OUT")"

        # Print "NAME:RES"
        printf "$NAME"
        printf ":$RES"
        printf "\n"
    done
done

printf "\nCPYTHON\n"
for i in {0..N}
do
    for bench in ./benchmarks/*.py
    do
        # Get benchmark name from path
        NAME=$(basename $bench)
        NAME="${NAME%.*}"

        # Run twopy with options and grep using key (e.g. "Executed tests: 120")
        OUT=$(/usr/bin/time -f "%e" python $bench | grep real)

        # Split using ":" and take 2nd element (e.g. 120)
        RES="$(cut -d':' -f2 <<<"$OUT")"

        # Print "NAME:RES"
        printf "$NAME"
        printf ":$RES"
        printf "\n"
    done
done