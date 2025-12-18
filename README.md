## run docker

```bash
sudo docker build -t opprf_fpsi:latest .

# docker tag opprf_fpsi:latest blueobsidian/opprf_fpsi:latest
# docker push blueobsidian/opprf_fpsi:latest

sudo docker run -dit --name opprf_fpsi --cap-add=NET_ADMIN opprf_fpsi:latest
```

```
tcset lo --rate 100Mbps --delay 80ms --overwrite
tcset lo --rate 10Mbps --delay 80ms --overwrite
```

```
nohup ./shell_run_bench_fmap.sh > opprf_fmap.log 2>&1 &
```
