

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

        printf "$NAME:"

        # Run twopy and print only the time
        OUT=$(PYTHONMALLOC=malloc /usr/bin/time -f "%e" ../cpython/python twopy.py  $bench | sed -n 1p)
    done
    printf "\n"
done

printf "TWOPY without BBV\n"
for i in {0..N}
do
    for bench in ./benchmarks/*.py
    do
        # Get benchmark name from path
        NAME=$(basename $bench)
        NAME="${NAME%.*}"

        printf "$NAME:"

        # Run twopy and print only the time
        OUT=$(PYTHONMALLOC=malloc /usr/bin/time -f "%e" ../cpython/python twopy.py --maxvers 0 $bench | sed -n 1p)
    done
    printf "\n"
done

printf "\nGraal VM\n"
for i in {0..N}
do
    for bench in ./benchmarks/*.py
    do
        # Get benchmark name from path
        NAME=$(basename $bench)
        NAME="${NAME%.*}"

        printf "$NAME:"

        # Run cpython
        OUT=$(/usr/bin/time -f "%e" /home/julien/Téléchargements/graalvm-ce-1.0.0-rc6/bin/graalpython $bench | sed -n 1p)
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

        printf "$NAME:"

        # Run pypy3
        OUT=$(/usr/bin/time -f "%e" pypy3 $bench | sed -n 1p)
    done
    printf "\n"
done

printf "\nCPYTHON\n"
for i in {0..N}
do
    for bench in ./benchmarks/*.py
    do
        # Get benchmark name from path
        NAME=$(basename $bench)
        NAME="${NAME%.*}"

        printf "$NAME:"

        # Run cpython
        OUT=$(/usr/bin/time -f "%e" python $bench | sed -n 1p)
    done
    printf "\n"
done

