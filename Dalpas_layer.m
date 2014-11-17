function status = Dalpas_layer(N, S)

%* Copyright (C) 2003 PARC Inc.  All Rights Reserved.
%*
%* Use, reproduction, preparation of derivative works, and distribution 
%* of this software is permitted, but only for non-commercial research 
%* or educational purposes. Any copy of this software or of any derivative 
%* work must include both the above copyright notice of PARC Incorporated 
%* and this paragraph. Any distribution of this software or derivative 
%* works must comply with all applicable United States export control laws. 
%* This software is made available AS IS, and PARC INCORPORATED DISCLAIMS 
%* ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE 
%* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
%* PURPOSE, AND NOTWITHSTANDING ANY OTHER PROVISION CONTAINED HEREIN, ANY 
%* LIABILITY FOR DAMAGES RESULTING FROM THE SOFTWARE OR ITS USE IS EXPRESSLY 
%* DISCLAIMED, WHETHER ARISING IN CONTRACT, TORT (INCLUDING NEGLIGENCE) 
%* OR STRICT LIABILITY, EVEN IF PARC INCORPORATED IS ADVISED OF THE 
%* POSSIBILITY OF SUCH DAMAGES. This notice applies to all files in this 
%* release (sources, executables, libraries, demos, and documentation).
%*

% Written by Ying Zhang, yzhang@parc.com
% Last modified: Nov. 22, 2003  by YZ

% DO NOT edit simulator code (lines that begin with S;)

S; %%%%%%%%%%%%%%%%%%%   housekeeping  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
S;      persistent app_data 
S;      global ID t
S;      [t, event, ID, data]=get_event(S);
S;      [topology, mote_IDs]=prowler('GetTopologyInfo');
S;      ix=find(mote_IDs==ID);
S;      if ~strcmp(event, 'Init_Application') 
S;         try memory=app_data{ix}; catch memory=[]; end, 
S;      end
S;      global ATTRIBUTES
S;      status = 1;
S;      pass = 1;
S; %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%                                          %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%         APPLICATION STARTS               %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%               HERE                       %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%                                          %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv%

global DESTINATIONS SOURCES
%global NEIGHBORS
global BufferSize Threshold AckStrength Perf_Thr_Delay
%global NQValues NHOPS NPOWERS FLAGS

%persistent DATA_M   = 10;
ACK      = -10;
INIT_H   = -33;
CONNECT  = -22;
BACK     = -66;

%Colors for Arrows
green    = [0.171 0.222 0.67];
blue     = [0.66 0.136 0.227];


switch event
case 'Init_Application'
    % SOURCES=zeros(1,100); c=[1, 7, 23, 12];  SOURCES(c)=1;
    % DESTINATIONS=zeros(1,100); d=[20, 99]; DESTINATIONS(d)=1;

    %%%%%%%%%%%%%%   Memory should be initialized here  %%%%%%%%%%%%%%%%%
    memory=struct('parent', -inf, 'hops', inf, 'hardStage', false, 'flag', true, 'queue', 0);
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  
    Set_Flood_Clock(1000);
        if (ix==1)
            sim_params('set_app', 'Promiscuous', 1);
            BufferSize = sim_params('get_app', 'BufferSize');
            if (isempty(BufferSize)) BufferSize = 150; end
            Threshold = sim_params('get_app', 'Threshold');
            if (isempty(Threshold)) Threshold = 100; end
            AckStrength = sim_params('get_app', 'AckStrength');
            if (isempty(AckStrength)) AckStrength = 1; end
            Perf_Thr_Delay = sim_params('get_app', 'Perf_Thr_Delay');
            if (isempty(Perf_Thr_Delay)) Perf_Thr_Delay = 20; end
        end
        
    %ATTRIBUTES{ID}.Hops = memory.hops;
    %ATTRIBUTES{ID}.QValue = 0;
    %ATTRIBUTES{ID}.flag = true; 
    %ATTRIBUTES{ID}.parent=-inf;
    %ATTRIBUTES{ID}.hardStage = false;
    %FLAGS(ID)=true;
    %NQValues{ID} = []; NHOPS{ID} = []; NPOWERS{ID} = [];   
    
case 'Send_Packet'
    try msgID = data.msgID; catch msgID=0; end
    if (msgID >= 0) 
    %Data message% 
        %data.address=memory.parent;
        if ~isfield(data,'address')
            pass = 0
            %PrintMessage(['forward to ->', num2str(data.address')]);
        end
        memory.parent = memory.queue - 1;
    elseif (msgID == INIT_H)  
        %initial message for hello
        %data.hops=memory.hops;
        %PrintMessage(['FLOODING HELLO ---', num2str(data.address')]);
    elseif (msgID == ACK)
        %initial message for hello
        %data.hops=memory.hops;
        %PrintMessage(['SENDING ACK ---', num2str(data.address')]);
    elseif (msgID == CONNECT)  
        %initial message for hello
        %data.hops=memory.hops;
        %PrintMessage(['ESTABLISHING 2-WAY CONNECTION ---', num2str(data.address')]);
    else
        disp(sprintf('Unrecognized Message ID in Send_Packet event'));
        disp(sprintf('in mote with id %d:\n',ID));
        disp(sprintf('Message Id %d:', data.msgID));
    end

%case 'Packet_Sent'    
%    try msgID = data.msgID; catch msgID = 0; end
%    if ((msgID < 0) && (~SOURCES(ID)))
%        ATTRIBUTES{ID}.QValue = ATTRIBUTES{ID}.QValue -1;
%    end    
    
        
case 'Packet_Received'
    if memory.queue > BufferSize
        pass = 0;
        return
    end
    
    try duplicated = data.duplicated; catch duplicated = 0; end
    if duplicated
        pass = 0;
        return
    end
    rdata = data.data;
    try msgID = rdata.msgID; catch msgID=0; end

    if DESTINATIONS(ID) && msgID > 0
        pass = 1;
        disp(sprintf('Succesfully arrived at Destination %d', ID));
    end
    %UPDATED NOVEMBER 2014
    switch msgID

        case INIT_H
            %Received a 'Hello' message for inital spantree formation
            if memory.parent < 0
                %send ack for two way handshake
                ack.from    = ID;
                ack.msgID   = ACK;
                ack.address = rdata.from;
                status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, ack));
                disp(sprintf('RX init - TX ack'));
                disp(sprintf('mote ID# %d:\n',ID));
                disp(rdata);
            end
            

        case ACK
            %received acknowledgment - acks are sent only during spantree initialization
            if rdata.address == ID
                connect.from    = ID;
                connect.msgID   = CONNECT;
                connect.address = rdata.from;
                connect.hops    = memory.hops;
                status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, connect));
                disp(sprintf('RX ack - TX conn'));
                disp(sprintf('mote ID# %d:\n',ID));
                disp(rdata);
            end
            

        case CONNECT
            %This is a twow way handshake
            memory.parent   = rdata.from;
            memory.hops     = rdata.hops + 1;
            hello.from      = ID;
            hello.msgID     = INIT_H;
            hello.address   = 0;
            hello.hops      = memory.hops;
            status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, hello));
            DrawLine('Arrow', memory.parent, ID, 'color', [0 0 0]);
            disp(sprintf('RX conn - TX hello'));
            disp(rdata);

        otherwise
            %real message - forward to next hop
            %first update queue
            memory.queue = memory.queue + 1;
            %then forward the message
            data            = rdata;
            data.address    = memory.parent;
            status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, data));
    end



%    if (msgID >= 0) %real data, forward to next hop
%        if (~DESTINATIONS(ID))
%           %rdata.forward=1; 
%            if (rdata.address==ID)      %5 && (ATTRIBUTES{ID}.queue_length < BufferSize || SOURCES(ID) )) %frward the packet
%            %ATTRIBUTES{ID}.QValue = ATTRIBUTES{ID}.QValue + 1;
%            status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, rdata));
%             end
%        else %this IS the Destinatoin
%            PrintMessage('rx');
%        end
%    elseif (msgID==-33) %flood data
%        %if (rdata.strength > 0.5)
%        nid= find(NEIGHBORS{ID}==rdata.from);
%        NHOPS{ID}(nid)= rdata.Hops; NPOWERS{ID}(nid)=rdata.power; NQValues{ID}(nid)=rdata.QValue;
%        if memory.parent<0
%            memory.parent=rdata.from;   
%            memory.hops=rdata.Hops+1; ATTRIBUTES{ID}.Hops=memory.hops;
%            rdata.from=ID;
%            rdata.Hops=memory.hops;
%            status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, rdata));
%            PrintMessage([num2str(memory.parent) '/' num2str(memory.hops)]);
%            DrawLine('Arrow', memory.parent, ID, 'color', [0 0 0])
%        else % memory.parent already exists
%            if (rdata.Hops+1 < memory.hops)
%                memory.parent=rdata.from;
%                memory.hops=rdata.Hops+1; ATTRIBUTES{ID}.Hops=memory.hops;
%                rdata.from=ID;
%                rdata.Hops=memory.hops;
%                status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, rdata));
%                %ATTRIBUTES{ID}.QValue = ATTRIBUTES{ID}.queue_length +1;
%                PrintMessage([num2str(memory.parent) '/' num2str(memory.hops)]);
%                DrawLine('Arrow', memory.parent, ID, 'color', [0 0 1])
%            end
%        end
%        %end
%
%    elseif (msgID==-66 && rdata.address==ID && (~ATTRIBUTES{ID}.hardStage) && rdata.from==memory.parent) 
%            PrintMessage(['cc' num2str(rdata.from)]);
%            neighs = NEIGHBORS{ID};
%            hops = NHOPS{ID};
%            powers = NPOWERS{ID};
%            buffers = NQValues{ID};
%            idr=find(NEIGHBORS{ID}==memory.parent);
%            neighs(idr)=[]; %remove from list
%            hops(idr)=[];   %remove from list
%            powers(idr)=[];
%            buffers(idr)=[];
%            idr=find(hops==min(hops));
%            if(~isempty(idr))
%            memory.parent=neighs(idr(1));
%            end
%            DrawLine('delete', memory.parent, ID);
%            DrawLine('Arrow', memory.parent, ID, 'color', [1 0 1]);
%
%            neighs =[]; hops=[]; %save space
%    elseif (msgID==-42)
%        if (rdata.from==memory.parent) 
%            ATTRIBUTES{ID}.parent = memory.parent;
%            memory.parent = flag_decision; 
%            if (memory.parent<0)
%                ATTRIBUTES{ID}.flag=false;
%                FLAGS(ID)=false;
%                ack.from=ID;
%                ack.msgID=-42;
%                status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, ack));
%            end
%        end
%    end
%    if (ATTRIBUTES{ID}.hardStage && ATTRIBUTES{ID}.queue_length > Threshold)
%        ATTRIBUTES{ID}.flag=false;
%        FLAGS(ID)=false;
%        ack.from=ID;
%        ack.msgID=-42;
%        status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, ack));
%        
%    end
%     %sys_stat=permstats;
%    if  ((ATTRIBUTES{ID}.queue_length >= BufferSize*0.9)&&(~SOURCES(ID))) %%((sys_stat.Average_Delays > Perf_Thr_Delay) || ((ATTRIBUTES{ID}.QValue >= BufferSize)&&(~SOURCES(ID)))) %%%%              
%        ATTRIBUTES{ID}.hardStage = true;
%    end

case 'Collided_Packet_Received'
    logevent('Collided',data.data);
        
case 'Clock_Tick'
  if (strcmp(data.type,'spantree_flood'))
      if DESTINATIONS(ID)
        memory.parent=ID;
        memory.hops=0; 
        %ATTRIBUTES{ID}.Hops=memory.hops;
        hello.from = ID;
        %fdata.power=ATTRIBUTES{ID}.power;
        hello.hops = 0;
        %fdata.QValue=0; 
        %fdata.flag=1;
        hello.msgID = INIT_H;
        hello.address = 0; %Broadcast
        %fdata.strength=ackStrength;
        status = Dalpas_layer(N, make_event(t, 'Send_Packet', ID, hello));
      end
      %pass = 0;
  end    
	    
case 'GuiInfoRequest'
    if ~isempty(memory)
        disp(sprintf('Memory Dump of mote ID# %d:\n',ID)); disp(memory)
        %disp(sprintf('q = %d:\n',ATTRIBUTES{ID}.queue_length));
        %disp(sprintf('Queue = %d:\n',ATTRIBUTES{ID}.queue_length));
        %disp(sprintf('Power = %d:\n',ATTRIBUTES{ID}.power));
        %disp(sprintf('Level =%d:\n',ATTRIBUTES{ID}.Hops));
        %disp(sprintf('UsedPower = %d:\n',ATTRIBUTES{ID}.usedPower));
    else
        disp(sprintf('No memory dump available for node %d.\n',ID)); 
    end
end %end switch

%^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%                                          %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%         APPLICATION ENDS                 %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%               HERE                       %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%                                          %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 
S; %%%%%%%%%%%%%%%%%%%%%% housekeeping %%%%%%%%%%%%%%%%%%%%%%%%%%%
S;        try app_data{ix}=memory; catch app_data{ix} = []; end
S;        if (pass) status = common_layer(N, make_event(t, event, ID, data)); end
S; %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%                           %%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%        COMMANDS           %%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%                           %%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


function b=Set_Flood_Clock(alarm_time);
global ID
data.type = 'spantree_flood';
prowler('InsertEvents2Q', make_event(alarm_time, 'Clock_Tick', ID, data));

%clock.type = 'spantree_flood';
%prowler('InsertEvents2Q', make_event(alarm_time, 'Clock_Tick', ID, clock));


function PrintMessage(msg)
global ID
prowler('TextMessage', ID, msg)

function DrawLine(command, varargin)
switch lower(command)
case 'line'
    prowler('DrawLine', varargin{:})
case 'arrow'
    prowler('DrawArrow', varargin{:})
case 'delete'
    prowler('DrawDelete', varargin{:})
otherwise
    error('Bad command for DrawLine.')
end

function [new_parent] = flag_decision
global ID  NEIGHBORS NHOPS NPOWERS NQValues FLAGS ATTRIBUTES
        neighs = NEIGHBORS{ID} ;
        hops = NHOPS{ID} ;
        powers = NPOWERS{ID} ;
        buffers = NQValues{ID};
        idr=find(NEIGHBORS{ID}==ATTRIBUTES{ID}.parent);
        neighs(idr)=[];
        hops(idr)=[];
        powers(idr)=[];
        buffers(idr)=[];        
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%        
        idr=find(FLAGS==false);
        for n=1:length(idr)
            x=find(neighs==(idr(n)));
            if (~isempty(x))
            neighs(x)=[];
            hops(x)=[];
            powers(x)=[];
            buffers(x)=[];
            end
        end
%        neighs(idr)=[];
 %       hops(idr)=[];
  %      powers(idr)=[];
   %     buffers(idr)=[];
       
        idr=find(hops==min(hops));
        if (length(idr)>1)
            idr=find(hops~=min(hops));
            neighs(idr)=[];
            hops(idr)=[];
            powers(idr)=[];
            buffers(idr)=[];
            idr=find(buffers==min(buffers));
		
            if (length(idr)==1) new_parent=neighs(idr(1)); neighs =[]; hops=[]; powers=[]; buffers=[]; return
            else
            idr=find(buffers~=min(buffers));
            neighs(idr)=[];
            buffers(idr)=[];   powers(idr)=[];             
            idr=find(powers==max(powers));  
            if (length(idr)>=1) new_parent=neighs(idr(1)); neighs =[]; hops=[]; powers=[]; buffers=[]; return 
            end
            end
        elseif (length(idr)==1) %length idr hops >1
        new_parent=neighs(idr(1)); neighs =[]; hops=[]; powers=[]; buffers=[]; return
        else new_parent=-99; return
        end %length idr hops >1
        neighs =[]; hops=[]; powers=[]; buffers=[]; %just to save space
        