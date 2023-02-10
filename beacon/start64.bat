set input=%1%
@echo off
mkdir release
clang++ --target=x86_64-pc-windows-msvc -c Global.cpp -o ./release/Global.o
clang++ --target=x86_64-pc-windows-msvc -c BeaconBof.cpp -o ./release/BeaconBof.o
clang++ --target=x86_64-pc-windows-msvc -c BeaconFileManage.cpp -o ./release/BeaconFileManage.o
clang++ --target=x86_64-pc-windows-msvc -c BeaconInject.cpp -o ./release/BeaconInject.o
clang++ --target=x86_64-pc-windows-msvc -c BeaconJob.cpp -o ./release/BeaconJob.o
clang++ --target=x86_64-pc-windows-msvc -c BeaconLateralMovement.cpp -o ./release/BeaconLateralMovement.o
clang++ --target=x86_64-pc-windows-msvc -c Beaconrportfwd.cpp -o ./release/Beaconrportfwd.o
clang++ --target=x86_64-pc-windows-msvc -c BeaconSleep.cpp -o ./release/BeaconSleep.o
clang++ --target=x86_64-pc-windows-msvc -c BeaconTask.cpp -o ./release/BeaconTask.o
clang++ --target=x86_64-pc-windows-msvc -c BeaconX64.cpp -o ./release/BeaconX64.o
clang++ --target=x86_64-pc-windows-msvc -c ChildBeacon.cpp -o ./release/ChildBeacon.o
clang++ --target=x86_64-pc-windows-msvc -c comm.cpp -o ./release/comm.o
clang++ --target=x86_64-pc-windows-msvc -c common.cpp -o ./release/common.o
clang++ --target=x86_64-pc-windows-msvc -c encrypt_decrypt.cpp -o ./release/encrypt_decrypt.o
clang++ --target=x86_64-pc-windows-msvc -c rotation.cpp -o ./release/rotation.o
clang++ --target=x86_64-pc-windows-msvc -c Utils.cpp -o ./release/Utils.o
echo "success" > %input%
exit