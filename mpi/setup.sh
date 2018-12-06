export OMPI_MCA_btl=^openib
echo export OMPI_MCA_btl=^openib>>.profile
scp ./mpi gt2-wilkinson@164.11.39.12:parallel-cw2/mpi
scp ./mpi gt2-wilkinson@164.11.39.13:parallel-cw2/mpi
scp ./mpi gt2-wilkinson@164.11.39.14:parallel-cw2/mpi
