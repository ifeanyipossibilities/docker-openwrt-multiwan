
config globals 'globals'
	option mmx_mask '0x3F00'
	option rtmon_interval '5'

config interface 'wan'
	option enabled '1'
	list track_ip '8.8.4.4'
	list track_ip '8.8.8.8'
	list track_ip '208.67.222.222'
	list track_ip '208.67.220.220'
	option family 'ipv4'
	option reliability '2'
	option count '1'
	option timeout '2'
	option failure_latency '1000'
	option recovery_latency '500'
	option failure_loss '20'
	option recovery_loss '5'
	option interval '5'
	option down '3'
	option up '8'

config rule 'https'
	option sticky '1'
	option dest_port '443'
	option proto 'tcp'
	option use_policy 'Balance_Wan'

config rule 'default_rule_v4'
	option dest_ip '0.0.0.0/0'
	option family 'ipv4'
	option proto 'all'
	option sticky '0'
	option use_policy 'Balance_Wan'

config rule 'default_rule_v6'
	option dest_ip '::/0'
	option family 'ipv6'
	option proto 'all'
	option sticky '0'
	option use_policy 'Balance_Wan'

config member 'M_W_1'
	option interface 'wan'
	option metric '1'
	option weight '1'


config policy 'Balance_Wan'
	list use_member 'M_W_1'
	option last_resort 'default'

config policy 'Fallover_Wan'
	list use_member 'M_W_1'
	option last_resort 'unreachable'





