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
clang++ --target=x86_64-pc-windows-msvc -c c2profile.cpp -o ./release/c2profile.o
clang++ --target=x86_64-pc-windows-msvc -L ./ beaconMain.cpp ./release/c2profile.o ./release/Utils.o ./release/rotation.o ./release/Global.o ./release/encrypt_decrypt.o ./release/common.o ./release/comm.o ./release/ChildBeacon.o ./release/BeaconX64.o ./release/BeaconTask.o ./release/BeaconSleep.o ./release/Beaconrportfwd.o ./release/BeaconLateralMovement.o ./release/BeaconJob.o ./release/BeaconInject.o ./release/BeaconFileManage.o ./release/BeaconBof.o -o ./release/beacon.exe
echo "success" > ../tt64