## run docker

```bash
sudo docker build -t fpsi_opprf:latest .

# docker tag fpsi_opprf:latest blueobsidian/fpsi_opprf:latest
# docker push blueobsidian/fpsi_opprf:latest

sudo docker run -dit --name fpsi_opprf --cap-add=NET_ADMIN fpsi_opprf:latest
sudo docker run -dit --name fpsi_opprf --cap-add=NET_ADMIN blueobsidian/fpsi_opprf:latest
```

```
tcset lo --rate 100Mbps --delay 80ms --overwrite
tcset lo --rate 10Mbps --delay 80ms --overwrite
```

```
nohup ./shell_run_bench_fmap.sh > opprf_fmap.log 2>&1 &
```
