function [param, i] = Dalpas_set_params(param, i, groupID)

i=i+1;
param(i).name='BufferSize';
param(i).default=15; %%%%%%% 960bits per packet = 120 bytes, 4KB/120 = 34packets
param(i).group=groupID;


i=i+1;
param(i).name='Threshold';
param(i).default= 12;
param(i).group=groupID;

i=i+1;
param(i).name='AckStrength';
param(i).default= 0.8;
param(i).group=groupID;

i=i+1;
param(i).name='Perf_Thr_Delay';
param(i).default= 2;
param(i).group=groupID;


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
