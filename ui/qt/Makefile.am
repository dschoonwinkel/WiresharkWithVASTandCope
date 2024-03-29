# Makefile.am
# Automake file for the Qt interface routines for Wireshark
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS) $(Qt_CFLAGS)

if HAVE_SPEEXDSP
AM_CPPFLAGS += $(SPEEXDSP_CFLAGS)
endif

# Define compatibility macros for Qt 4.8
if HAVE_QT_VERSION_4
AM_CPPFLAGS += -DQ_NULLPTR=NULL
endif

noinst_LIBRARIES = libqtui.a

include Makefile_custom.common

# Generated header files that we want in the distribution.
GENERATED_HEADER_FILES =

# Generated header files that we don't want in the distribution.
NODIST_GENERATED_HEADER_FILES = \
	ui_about_dialog.h				\
	ui_address_editor_frame.h			\
	ui_bluetooth_att_server_attributes_dialog.h	\
	ui_bluetooth_device_dialog.h			\
	ui_bluetooth_devices_dialog.h			\
	ui_bluetooth_hci_summary_dialog.h		\
	ui_capture_file_properties_dialog.h		\
	ui_capture_interfaces_dialog.h			\
	ui_capture_preferences_frame.h			\
	ui_coloring_rules_dialog.h			\
	ui_column_preferences_frame.h			\
	ui_column_editor_frame.h			\
	ui_compiled_filter_output.h			\
	ui_conversation_hash_tables_dialog.h		\
	ui_decode_as_dialog.h				\
	ui_display_filter_expression_dialog.h		\
	ui_dissector_tables_dialog.h			\
	ui_enabled_protocols_dialog.h			\
	ui_expert_info_dialog.h				\
	ui_export_object_dialog.h			\
	ui_export_pdu_dialog.h				\
	ui_extcap_options_dialog.h			\
	ui_file_set_dialog.h				\
	ui_filter_dialog.h				\
	ui_filter_expression_frame.h			\
	ui_firewall_rules_dialog.h			\
	ui_follow_stream_dialog.h			\
	ui_font_color_preferences_frame.h		\
	ui_funnel_string_dialog.h			\
	ui_funnel_text_dialog.h				\
	ui_gsm_map_summary_dialog.h			\
	ui_iax2_analysis_dialog.h			\
	ui_import_text_dialog.h				\
	ui_interface_frame.h				\
	ui_interface_toolbar.h				\
	ui_io_graph_dialog.h				\
	ui_layout_preferences_frame.h			\
	ui_lbm_lbtrm_transport_dialog.h			\
	ui_lbm_lbtru_transport_dialog.h			\
	ui_lbm_stream_dialog.h				\
	ui_lbm_uimflow_dialog.h				\
	ui_lte_rlc_graph_dialog.h			\
	ui_main_welcome.h				\
	ui_main_window.h				\
	ui_main_window_preferences_frame.h		\
	ui_manage_interfaces_dialog.h			\
	ui_module_preferences_scroll_area.h		\
	ui_mtp3_summary_dialog.h			\
	ui_overlay_scroll_bar.h				\
	ui_packet_comment_dialog.h			\
	ui_packet_dialog.h				\
	ui_packet_format_group_box.h			\
	ui_packet_range_group_box.h			\
	ui_preference_editor_frame.h			\
	ui_preferences_dialog.h				\
	ui_print_dialog.h				\
	ui_profile_dialog.h				\
	ui_progress_frame.h				\
	ui_protocol_hierarchy_dialog.h			\
	ui_remote_capture_dialog.h			\
	ui_remote_settings_dialog.h			\
	ui_resolved_addresses_dialog.h			\
	ui_rtp_analysis_dialog.h			\
	ui_rtp_player_dialog.h				\
	ui_rtp_stream_dialog.h				\
	ui_sctp_all_assocs_dialog.h			\
	ui_sctp_assoc_analyse_dialog.h			\
	ui_sctp_chunk_statistics_dialog.h		\
	ui_sctp_graph_dialog.h				\
	ui_sctp_graph_arwnd_dialog.h			\
	ui_sctp_graph_byte_dialog.h			\
	ui_search_frame.h				\
	ui_sequence_dialog.h				\
	ui_show_packet_bytes_dialog.h			\
	ui_splash_overlay.h				\
	ui_supported_protocols_dialog.h			\
	ui_tap_parameter_dialog.h			\
	ui_tcp_stream_dialog.h				\
	ui_time_shift_dialog.h				\
	ui_traffic_table_dialog.h			\
	ui_uat_dialog.h					\
	ui_uat_frame.h					\
	ui_voip_calls_dialog.h				\
	ui_wireless_frame.h


# Generated C source files that we want in the distribution.
GENERATED_C_FILES =

# Generated C source files that we don't want in the distribution.
NODIST_GENERATED_C_FILES = \
	wireshark-tap-register.c

# Generated C++ source files that we want in the distribution.
GENERATED_CPP_FILES =

# Generated C++ source files that we don't want in the distribution.
NODIST_GENERATED_CPP_FILES = \
	$(MOC_SRC)	\
	$(QRC_SRC)

# All the generated files we want in the distribution.
GENERATED_FILES = \
	$(GENERATED_HEADER_FILES)	\
	$(GENERATED_C_FILES)		\
	$(GENERATED_CPP_FILES)

# All the generated files we don't want in the distribution.
NODIST_GENERATED_FILES = \
	$(NODIST_GENERATED_HEADER_FILES)	\
	$(NODIST_GENERATED_C_FILES)		\
	$(NODIST_GENERATED_CPP_FILES)

# Files that generate compileable files
GENERATOR_FILES =

# Files that are basic widgets for every tool to be used
MOC_WIDGET_HDRS = \
	widgets/additional_toolbar.h			\
	widgets/apply_line_edit.h			\
	widgets/byte_view_text.h			\
	widgets/capture_filter_combo.h			\
	widgets/capture_filter_edit.h			\
	widgets/clickable_label.h			\
	widgets/display_filter_combo.h			\
	widgets/display_filter_edit.h			\
	widgets/dissector_tables_view.h			\
	widgets/drag_drop_toolbar.h			\
	widgets/drag_label.h			\
	widgets/editor_color_dialog.h				\
	widgets/editor_file_dialog.h				\
	widgets/elided_label.h				\
	widgets/expert_info_view.h			\
	widgets/export_objects_view.h				\
	widgets/field_filter_edit.h			\
	widgets/find_line_edit.h			\
	widgets/follow_stream_text.h			\
	widgets/interface_toolbar_lineedit.h		\
	widgets/label_stack.h				\
	widgets/overlay_scroll_bar.h			\
	widgets/pref_module_view.h			\
	widgets/range_syntax_lineedit.h			\
	widgets/syntax_line_edit.h			\
	widgets/stock_icon_tool_button.h		\
	widgets/tabnav_tree_view.h			\
	widgets/wireshark_file_dialog.h			\
	widgets/qcustomplot.h


# Files that are general manager classes with
MOC_MANAGER_HDRS = \
	manager/preference_manager.h			\
	manager/wireshark_preference.h

# Files that are utility classes with multi-purpose, but no widgets
MOC_UTILS_HDRS = \
	utils/color_utils.h				\
	utils/data_printer.h				\
	utils/field_information.h			\
	utils/frame_information.h			\
	utils/idata_printable.h				\
	utils/proto_node.h				\
	utils/qt_ui_utils.h				\
	utils/stock_icon.h				\
	utils/variant_pointer.h				\
	utils/wireshark_mime_data.h

# Files for delegates and models
MOC_MODELS_HDRS = \
	models/astringlist_list_model.h			\
	models/cache_proxy_model.h			\
	models/coloring_rules_delegate.h			\
	models/coloring_rules_model.h			\
	models/decode_as_delegate.h			\
	models/decode_as_model.h			\
	models/dissector_tables_model.h			\
	models/enabled_protocols_model.h			\
	models/expert_info_model.h			\
	models/expert_info_proxy_model.h		\
	models/export_objects_model.h			\
	models/fileset_entry_model.h			\
	models/info_proxy_model.h			\
	models/interface_sort_filter_model.h		\
	models/interface_tree_cache_model.h		\
	models/interface_tree_model.h			\
	models/numeric_value_chooser_delegate.h		\
	models/packet_list_model.h			\
	models/packet_list_record.h			\
	models/path_chooser_delegate.h			\
	models/percent_bar_delegate.h			\
	models/pref_delegate.h			\
	models/pref_models.h			\
	models/proto_tree_model.h			\
	models/related_packet_delegate.h		\
	models/sparkline_delegate.h			\
	models/supported_protocols_model.h		\
	models/timeline_delegate.h			\
	models/tree_model_helpers.h			\
	models/uat_delegate.h				\
	models/uat_model.h				\
	models/url_link_delegate.h			\
	models/voip_calls_info_model.h


#
# Headers that have to be run through moc.
#
MOC_HDRS = \
	about_dialog.h					\
	accordion_frame.h				\
	address_editor_frame.h				\
	bluetooth_att_server_attributes_dialog.h	\
	bluetooth_device_dialog.h			\
	bluetooth_devices_dialog.h			\
	bluetooth_hci_summary_dialog.h			\
	byte_view_tab.h					\
	capture_file.h					\
	capture_file_dialog.h				\
	capture_file_properties_dialog.h		\
	capture_filter_syntax_worker.h			\
	capture_info_dialog.h				\
	capture_interfaces_dialog.h			\
	capture_preferences_frame.h			\
	coloring_rules_dialog.h				\
	column_preferences_frame.h			\
	column_editor_frame.h				\
	compiled_filter_output.h			\
	conversation_colorize_action.h			\
	conversation_dialog.h				\
	conversation_hash_tables_dialog.h		\
	decode_as_dialog.h				\
	display_filter_expression_dialog.h		\
	dissector_tables_dialog.h			\
	enabled_protocols_dialog.h			\
	endpoint_dialog.h				\
	expert_info_dialog.h				\
	export_dissection_dialog.h			\
	export_object_action.h				\
	export_object_dialog.h				\
	export_pdu_dialog.h				\
	extcap_argument.h		\
	extcap_argument_file.h		\
	extcap_argument_multiselect.h	\
	extcap_options_dialog.h			\
	file_set_dialog.h				\
	filter_action.h					\
	filter_dialog.h					\
	filter_expression_frame.h			\
	firewall_rules_dialog.h				\
	follow_stream_dialog.h				\
	font_color_preferences_frame.h			\
	funnel_string_dialog.h				\
	funnel_text_dialog.h				\
	funnel_statistics.h				\
	geometry_state_dialog.h				\
	gsm_map_summary_dialog.h			\
	iax2_analysis_dialog.h				\
	import_text_dialog.h				\
	interface_frame.h				\
	interface_toolbar.h				\
	interface_toolbar_reader.h			\
	io_graph_dialog.h				\
	layout_preferences_frame.h			\
	lbm_lbtrm_transport_dialog.h			\
	lbm_lbtru_transport_dialog.h			\
	lbm_stream_dialog.h				\
	lte_mac_statistics_dialog.h			\
	lte_rlc_graph_dialog.h				\
	lte_rlc_statistics_dialog.h			\
	main_status_bar.h				\
	main_welcome.h					\
	main_window.h					\
	main_window_preferences_frame.h			\
	manage_interfaces_dialog.h			\
	module_preferences_scroll_area.h		\
	multicast_statistics_dialog.h			\
	mtp3_summary_dialog.h				\
	packet_comment_dialog.h				\
	packet_dialog.h					\
	packet_format_group_box.h			\
	packet_list.h					\
	packet_range_group_box.h			\
	preference_editor_frame.h			\
	preferences_dialog.h				\
	print_dialog.h					\
	profile_dialog.h				\
	progress_frame.h				\
	proto_tree.h					\
	protocol_hierarchy_dialog.h			\
	protocol_preferences_menu.h			\
	recent_file_status.h				\
	remote_capture_dialog.h				\
	remote_settings_dialog.h			\
	resolved_addresses_dialog.h			\
	response_time_delay_dialog.h			\
	rpc_service_response_time_dialog.h		\
	rtp_analysis_dialog.h				\
	rtp_audio_stream.h				\
	rtp_player_dialog.h				\
	rtp_stream_dialog.h				\
	scsi_service_response_time_dialog.h		\
	sctp_all_assocs_dialog.h			\
	sctp_assoc_analyse_dialog.h			\
	search_frame.h					\
	sctp_chunk_statistics_dialog.h			\
	sctp_graph_dialog.h				\
	sctp_graph_arwnd_dialog.h			\
	sctp_graph_byte_dialog.h			\
	search_frame.h					\
	sequence_diagram.h				\
	sequence_dialog.h				\
	service_response_time_dialog.h			\
	show_packet_bytes_dialog.h			\
	simple_statistics_dialog.h			\
	splash_overlay.h				\
	stats_tree_dialog.h				\
	supported_protocols_dialog.h			\
	tabnav_tree_widget.h				\
	tap_parameter_dialog.h				\
	tcp_stream_dialog.h				\
	time_shift_dialog.h				\
	traffic_table_dialog.h				\
	uat_dialog.h					\
	uat_frame.h					\
	voip_calls_dialog.h				\
	wireless_frame.h				\
	wireless_timeline.h				\
	wireshark_application.h				\
	wireshark_dialog.h				\
	wlan_statistics_dialog.h			\
	$(MOC_WIDGET_HDRS)				\
	$(MOC_MANAGER_HDRS)				\
	$(MOC_UTILS_HDRS)				\
	$(MOC_MODELS_HDRS)

#
# .ui files.
#
UI_FILES = \
	about_dialog.ui					\
	address_editor_frame.ui				\
	bluetooth_att_server_attributes_dialog.ui	\
	bluetooth_device_dialog.ui			\
	bluetooth_devices_dialog.ui			\
	bluetooth_hci_summary_dialog.ui			\
	capture_file_properties_dialog.ui 		\
	capture_interfaces_dialog.ui 			\
	capture_preferences_frame.ui			\
	coloring_rules_dialog.ui			\
	column_preferences_frame.ui			\
	column_editor_frame.ui				\
	compiled_filter_output.ui 			\
	conversation_hash_tables_dialog.ui		\
	decode_as_dialog.ui				\
	display_filter_expression_dialog.ui		\
	dissector_tables_dialog.ui			\
	enabled_protocols_dialog.ui			\
	expert_info_dialog.ui				\
	export_object_dialog.ui				\
	export_pdu_dialog.ui				\
	extcap_options_dialog.ui			\
	file_set_dialog.ui				\
	filter_dialog.ui				\
	filter_expression_frame.ui			\
	firewall_rules_dialog.ui			\
	follow_stream_dialog.ui				\
	font_color_preferences_frame.ui			\
	funnel_string_dialog.ui				\
	funnel_text_dialog.ui				\
	gsm_map_summary_dialog.ui			\
	iax2_analysis_dialog.ui				\
	import_text_dialog.ui				\
	interface_frame.ui				\
	interface_toolbar.ui				\
	io_graph_dialog.ui				\
	layout_preferences_frame.ui			\
	lbm_lbtrm_transport_dialog.ui			\
	lbm_lbtru_transport_dialog.ui			\
	lbm_stream_dialog.ui				\
	lte_rlc_graph_dialog.ui				\
	main_welcome.ui					\
	main_window.ui					\
	main_window_preferences_frame.ui		\
	manage_interfaces_dialog.ui			\
	module_preferences_scroll_area.ui		\
	mtp3_summary_dialog.ui				\
	packet_format_group_box.ui			\
	packet_range_group_box.ui			\
	packet_comment_dialog.ui			\
	packet_dialog.ui				\
	preference_editor_frame.ui			\
	preferences_dialog.ui				\
	print_dialog.ui					\
	profile_dialog.ui				\
	progress_frame.ui				\
	protocol_hierarchy_dialog.ui			\
	remote_capture_dialog.ui			\
	remote_settings_dialog.ui			\
	resolved_addresses_dialog.ui			\
	rtp_analysis_dialog.ui				\
	rtp_player_dialog.ui				\
	rtp_stream_dialog.ui				\
	sctp_all_assocs_dialog.ui			\
	sctp_assoc_analyse_dialog.ui			\
	sctp_chunk_statistics_dialog.ui			\
	sctp_graph_dialog.ui				\
	sctp_graph_arwnd_dialog.ui			\
	sctp_graph_byte_dialog.ui			\
	search_frame.ui					\
	sequence_dialog.ui				\
	show_packet_bytes_dialog.ui			\
	splash_overlay.ui				\
	supported_protocols_dialog.ui			\
	tap_parameter_dialog.ui				\
	tcp_stream_dialog.ui				\
	time_shift_dialog.ui				\
	traffic_table_dialog.ui				\
	uat_dialog.ui					\
	uat_frame.ui					\
	voip_calls_dialog.ui				\
	wireless_frame.ui

#
# The .moc.cpp files generated from them.
# We do *not* include these in the distribution; if you have the Qt SDK
# installed, so that you can build Qt-based applications, you have moc
# installed.
#
MOC_SRC = $(MOC_HDRS:.h=.moc.cpp)

#
# .qrc files.
#
# Should QRC_FILES or QRC_SRC depend on QRC_IMAGES?
QRC_FILES = \
	../../image/about.qrc			\
	../../image/languages/languages.qrc	\
	../../image/layout.qrc			\
	../../image/stock_icons.qrc		\
	../../image/wsicon.qrc

#
# The .cpp files generated from them.
# We do *not* include these in the distribution; if you have the Qt SDK
# installed, so that you can build Qt-based applications, you have rcc
# installed.
#
QRC_SRC = \
	qrc_about.cpp		\
	qrc_languages.cpp	\
	qrc_layout.cpp		\
	qrc_stock_icons.cpp	\
	qrc_wsicon.cpp		\
	qrc_i18n.cpp

#
# .ts files.
# wireshark_en should be pluralonly.
#
TS_FILES = \
	wireshark_de.ts		\
	wireshark_en.ts		\
	wireshark_fr.ts		\
	wireshark_it.ts 	\
	wireshark_ja_JP.ts	\
	wireshark_pl.ts		\
	wireshark_zh_CN.ts

#
# .qm files.
#
QM_FILES = $(TS_FILES:.ts=.qm)

WIRESHARK_QT_WIDGET_SRC = \
	widgets/additional_toolbar.cpp			\
	widgets/apply_line_edit.cpp			\
	widgets/byte_view_text.cpp			\
	widgets/capture_filter_combo.cpp		\
	widgets/capture_filter_edit.cpp			\
	widgets/clickable_label.cpp			\
	widgets/display_filter_combo.cpp		\
	widgets/display_filter_edit.cpp			\
	widgets/dissector_tables_view.cpp			\
	widgets/drag_drop_toolbar.cpp			\
	widgets/drag_label.cpp			\
	widgets/editor_color_dialog.cpp			\
	widgets/editor_file_dialog.cpp			\
	widgets/elided_label.cpp			\
	widgets/expert_info_view.cpp			\
	widgets/export_objects_view.cpp			\
	widgets/field_filter_edit.cpp			\
	widgets/find_line_edit.cpp			\
	widgets/follow_stream_text.cpp			\
	widgets/interface_toolbar_lineedit.cpp		\
	widgets/label_stack.cpp				\
	widgets/overlay_scroll_bar.cpp			\
	widgets/pref_module_view.cpp			\
	widgets/stock_icon_tool_button.cpp		\
	widgets/range_syntax_lineedit.cpp		\
	widgets/syntax_line_edit.cpp			\
	widgets/tabnav_tree_view.cpp			\
	widgets/wireshark_file_dialog.cpp		\
	widgets/qcustomplot.cpp

# Files that are general manager classes with
WIRESHARK_QT_MANAGER_SRC = \
	manager/preference_manager.cpp			\
	manager/wireshark_preference.cpp

WIRESHARK_QT_UTILS_SRC = \
	utils/color_utils.cpp				\
	utils/data_printer.cpp				\
	utils/field_information.cpp			\
	utils/frame_information.cpp			\
	utils/proto_node.cpp				\
	utils/qt_ui_utils.cpp				\
	utils/stock_icon.cpp				\
	utils/wireshark_mime_data.cpp

WIRESHARK_QT_MODELS_SRCS = \
	models/astringlist_list_model.cpp		\
	models/cache_proxy_model.cpp			\
	models/coloring_rules_delegate.cpp			\
	models/coloring_rules_model.cpp			\
	models/decode_as_delegate.cpp			\
	models/decode_as_model.cpp			\
	models/dissector_tables_model.cpp			\
	models/enabled_protocols_model.cpp			\
	models/expert_info_model.cpp			\
	models/expert_info_proxy_model.cpp		\
	models/export_objects_model.cpp			\
	models/fileset_entry_model.cpp			\
	models/info_proxy_model.cpp			\
	models/interface_sort_filter_model.cpp		\
	models/interface_tree_cache_model.cpp		\
	models/interface_tree_model.cpp			\
	models/numeric_value_chooser_delegate.cpp	\
	models/packet_list_model.cpp			\
	models/packet_list_record.cpp			\
	models/path_chooser_delegate.cpp		\
	models/percent_bar_delegate.cpp			\
	models/pref_delegate.cpp			\
	models/pref_models.cpp			\
	models/proto_tree_model.cpp			\
	models/related_packet_delegate.cpp		\
	models/sparkline_delegate.cpp			\
	models/supported_protocols_model.cpp		\
	models/timeline_delegate.cpp			\
	models/uat_model.cpp				\
	models/uat_delegate.cpp				\
	models/url_link_delegate.cpp			\
	models/voip_calls_info_model.cpp

WIRESHARK_QT_SRC = \
	about_dialog.cpp				\
	accordion_frame.cpp				\
	address_editor_frame.cpp			\
	bluetooth_att_server_attributes_dialog.cpp	\
	bluetooth_device_dialog.cpp			\
	bluetooth_devices_dialog.cpp			\
	bluetooth_hci_summary_dialog.cpp		\
	byte_view_tab.cpp				\
	capture_file.cpp				\
	capture_file_dialog.cpp				\
	capture_file_properties_dialog.cpp		\
	capture_filter_syntax_worker.cpp		\
	capture_info_dialog.cpp				\
	capture_interfaces_dialog.cpp			\
	capture_preferences_frame.cpp			\
	coloring_rules_dialog.cpp			\
	column_preferences_frame.cpp			\
	column_editor_frame.cpp				\
	compiled_filter_output.cpp			\
	conversation_colorize_action.cpp		\
	conversation_dialog.cpp				\
	conversation_hash_tables_dialog.cpp		\
	decode_as_dialog.cpp				\
	display_filter_expression_dialog.cpp		\
	dissector_tables_dialog.cpp			\
	enabled_protocols_dialog.cpp			\
	endpoint_dialog.cpp				\
	export_dissection_dialog.cpp			\
	export_object_action.cpp			\
	export_object_dialog.cpp			\
	export_pdu_dialog.cpp				\
	extcap_argument.cpp			\
	extcap_argument_file.cpp	\
	extcap_argument_multiselect.cpp	\
	extcap_options_dialog.cpp		\
	file_set_dialog.cpp				\
	filter_action.cpp				\
	filter_dialog.cpp				\
	filter_expression_frame.cpp			\
	firewall_rules_dialog.cpp			\
	follow_stream_dialog.cpp			\
	font_color_preferences_frame.cpp		\
	funnel_string_dialog.cpp			\
	funnel_text_dialog.cpp				\
	geometry_state_dialog.cpp			\
	iax2_analysis_dialog.cpp			\
	import_text_dialog.cpp				\
	interface_frame.cpp				\
	interface_toolbar.cpp				\
	interface_toolbar_reader.cpp			\
	layout_preferences_frame.cpp			\
	lbm_lbtrm_transport_dialog.cpp			\
	lbm_lbtru_transport_dialog.cpp			\
	lbm_stream_dialog.cpp				\
	lte_mac_statistics_dialog.cpp			\
	lte_rlc_graph_dialog.cpp			\
	lte_rlc_statistics_dialog.cpp			\
	main_status_bar.cpp				\
	main_welcome.cpp				\
	main_window.cpp					\
	main_window_preferences_frame.cpp		\
	main_window_slots.cpp				\
	manage_interfaces_dialog.cpp			\
	module_preferences_scroll_area.cpp		\
	packet_comment_dialog.cpp			\
	packet_dialog.cpp				\
	packet_format_group_box.cpp			\
	packet_list.cpp					\
	packet_range_group_box.cpp			\
	preference_editor_frame.cpp			\
	preferences_dialog.cpp				\
	print_dialog.cpp				\
	profile_dialog.cpp				\
	progress_frame.cpp				\
	proto_tree.cpp					\
	protocol_hierarchy_dialog.cpp			\
	protocol_preferences_menu.cpp			\
	recent_file_status.cpp				\
	remote_capture_dialog.cpp			\
	remote_settings_dialog.cpp			\
	resolved_addresses_dialog.cpp			\
	response_time_delay_dialog.cpp			\
	rpc_service_response_time_dialog.cpp		\
	rtp_analysis_dialog.cpp				\
	rtp_audio_stream.cpp				\
	rtp_player_dialog.cpp				\
	rtp_stream_dialog.cpp				\
	scsi_service_response_time_dialog.cpp		\
	sctp_all_assocs_dialog.cpp			\
	sctp_assoc_analyse_dialog.cpp			\
	sctp_chunk_statistics_dialog.cpp		\
	sctp_graph_dialog.cpp				\
	sctp_graph_arwnd_dialog.cpp			\
	sctp_graph_byte_dialog.cpp			\
	search_frame.cpp				\
	sequence_diagram.cpp				\
	sequence_dialog.cpp				\
	service_response_time_dialog.cpp		\
	show_packet_bytes_dialog.cpp			\
	simple_dialog.cpp				\
	simple_statistics_dialog.cpp			\
	splash_overlay.cpp				\
	supported_protocols_dialog.cpp			\
	tabnav_tree_widget.cpp				\
	tap_parameter_dialog.cpp			\
	tcp_stream_dialog.cpp				\
	time_shift_dialog.cpp				\
	traffic_table_dialog.cpp			\
	uat_dialog.cpp					\
	uat_frame.cpp					\
	voip_calls_dialog.cpp				\
	wireless_frame.cpp				\
	wireless_timeline.cpp				\
	wireshark_application.cpp			\
	wireshark_dialog.cpp				\
	$(WIRESHARK_QT_WIDGET_SRC)			\
	$(WIRESHARK_QT_UTILS_SRC)			\
	$(WIRESHARK_QT_MANAGER_SRC)			\
	${WIRESHARK_QT_MODELS_SRCS}

WIRESHARK_QT_TAP_SRC = \
	expert_info_dialog.cpp			\
	funnel_statistics.cpp			\
	gsm_map_summary_dialog.cpp		\
	io_graph_dialog.cpp			\
	lte_mac_statistics_dialog.cpp		\
	lte_rlc_statistics_dialog.cpp		\
	mtp3_summary_dialog.cpp			\
	multicast_statistics_dialog.cpp		\
	rtp_stream_dialog.cpp			\
	sctp_all_assocs_dialog.cpp		\
	sctp_assoc_analyse_dialog.cpp		\
	stats_tree_dialog.cpp			\
	wlan_statistics_dialog.cpp

noinst_HEADERS = \
	$(MOC_HDRS)			\
	capture_event.h			\
	simple_dialog.h			\
	models/packet_list_record.h	\
	widgets/qcustomplot.h		\
	utils/qt_ui_utils.h		\
	utils/stock_icon.h		\
	utils/tango_colors.h		\
	utils/variant_pointer.h


wireshark-tap-register.c: $(WIRESHARK_QT_TAP_SRC) ../make-taps
	$(AM_V_GEN)../make-taps $@ $(filter %.cpp,$^)

libqtui_a_SOURCES = \
	$(WIRESHARK_QT_SRC)		\
	$(WIRESHARK_QT_TAP_SRC)		\
	$(GENERATED_C_FILES)		\
	$(GENERATED_CPP_FILES)		\
	$(noinst_HEADERS)		\
	$(GENERATED_HEADER_FILES)

nodist_libqtui_a_SOURCES = \
	$(NODIST_GENERATED_C_FILES)	\
	$(NODIST_GENERATED_CPP_FILES)	\
	$(NODIST_GENERATED_HEADER_FILES)

CLEANFILES = \
	*.moc.cpp			\
	qrc_*.cpp			\
	ui_*.h

DISTCLEANFILES = \
	$(NODIST_GENERATED_FILES)	\
	$(QM_FILES)		\
	i18n.qrc

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)

AM_V_MOC = $(am__v_MOC_@AM_V@)
am__v_MOC_ = $(am__v_MOC_@AM_DEFAULT_V@)
am__v_MOC_0 = @echo "  MOC     " $@;

AM_V_RCC = $(am__v_RCC_@AM_V@)
am__v_RCC_ = $(am__v_RCC_@AM_DEFAULT_V@)
am__v_RCC_0 = @echo "  RCC     " $@;

AM_V_UIC = $(am__v_UIC_@AM_V@)
am__v_UIC_ = $(am__v_UIC_@AM_DEFAULT_V@)
am__v_UIC_0 = @echo "  UIC     " $@;

AM_V_LRELEASE = $(am__v_LRELEASE_@AM_V@)
am__v_LRELEASE_ = $(am__v_LRELEASE_@AM_DEFAULT_V@)
am__v_LRELEASE_0 = @echo "  LRELEASE  " $@;

#
# For building .moc.cpp files from .h files by running moc,
# building .rcc.cpp files from .qrc files by running rcc,
# and building ui_XXX.h files from .ui files by running uic.
#
SUFFIXES = .moc.cpp

#
# The Qt toolchain uses the naming convention moc_FOO.cpp. Should we do the same?
#moc_%.cpp: %.h
#	$(MOC) $< -o $@
#
.h.moc.cpp:
	$(AM_V_MOC)$(MOC) $(MOC_OPTIONS) -I.. -I../.. $(INCLUDEDIRS) -o $@ $<

qrc_about.cpp: ../../image/about.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name about -o $@ $<

qrc_layout.cpp: ../../image/layout.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name layout -o $@ $<

qrc_languages.cpp: ../../image/languages/languages.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name languages -o $@ $<

qrc_i18n.cpp: i18n.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name i18n -o $@ $<

qrc_stock_icons.cpp: ../../image/stock_icons.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name stock_icons -o $@ $<

qrc_wsicon.cpp: ../../image/wsicon.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name wsicon -o $@ $<

ui_%.h: %.ui
	$(AM_V_UIC)$(UIC) $< -o $@

wireshark_%.qm: wireshark_%.ts
	$(AM_V_LRELEASE)$(LRELEASE) -silent $< -qm $@

i18n_qresource := $(foreach qm, $(QM_FILES),<file>$(qm)</file>)

i18n.qrc: i18n.qrc.in $(QM_FILES)
	$(AM_V_SED)$(SED) \
		-e 's,@i18n_qresource\@,$(i18n_qresource),' \
		-e 's,> *<file>,>%    <file>,g' \
		< $< | tr '%' '\n' > $@

#
# Explicit dependencies to force the ui_ headers to be built.
# See "Recording Dependencies manually" in the "Built Sources"
# section of the automake documentation:
#
#    https://www.gnu.org/software/automake/manual/automake.html#Sources
#
about_dialog.$(OBJEXT): ui_about_dialog.h

address_editor_frame.$(OBJEXT): ui_address_editor_frame.h

bluetooth_att_server_attributes_dialog.$(OBJEXT): ui_bluetooth_att_server_attributes_dialog.h

bluetooth_devices_dialog.$(OBJEXT): ui_bluetooth_devices_dialog.h

bluetooth_device_dialog.$(OBJEXT): ui_bluetooth_device_dialog.h

bluetooth_hci_summary_dialog.$(OBJEXT): ui_bluetooth_hci_summary_dialog.h

capture_file_properties_dialog.$(OBJEXT): ui_capture_file_properties_dialog.h

capture_interfaces_dialog.$(OBJEXT): ui_capture_interfaces_dialog.h

capture_preferences_frame.$(OBJEXT): ui_capture_preferences_frame.h

coloring_rules_dialog.$(OBJEXT): ui_coloring_rules_dialog.h

column_editor_frame.$(OBJEXT): ui_column_editor_frame.h

column_preferences_frame.$(OBJEXT): ui_column_preferences_frame.h

compiled_filter_output.$(OBJEXT): ui_compiled_filter_output.h

conversation_hash_tables_dialog.$(OBJEXT): ui_conversation_hash_tables_dialog.h

decode_as_dialog.$(OBJEXT): ui_decode_as_dialog.h

display_filter_expression_dialog.$(OBJEXT): ui_display_filter_expression_dialog.h

dissector_tables_dialog.$(OBJEXT): ui_dissector_tables_dialog.h

enabled_protocols_dialog.$(OBJEXT): ui_enabled_protocols_dialog.h

expert_info_dialog.$(OBJEXT): ui_expert_info_dialog.h

export_object_dialog.$(OBJEXT): ui_export_object_dialog.h

export_pdu_dialog.$(OBJEXT): ui_export_pdu_dialog.h

extcap_options_dialog.$(OBJEXT): ui_extcap_options_dialog.h

file_set_dialog.$(OBJEXT): ui_file_set_dialog.h

filter_dialog.$(OBJEXT): ui_filter_dialog.h

filter_expression_frame.$(OBJEXT): ui_filter_expression_frame.h

firewall_rules_dialog.$(OBJEXT): ui_firewall_rules_dialog.h

follow_stream_dialog.$(OBJEXT): ui_follow_stream_dialog.h

font_color_preferences_frame.$(OBJEXT): ui_font_color_preferences_frame.h

funnel_string_dialog.$(OBJEXT): ui_funnel_string_dialog.h

funnel_text_dialog.$(OBJEXT): ui_funnel_text_dialog.h

gsm_map_summary_dialog.$(OBJEXT): ui_gsm_map_summary_dialog.h

iax2_analysis_dialog.$(OBJEXT): ui_iax2_analysis_dialog.h

import_text_dialog.$(OBJEXT): ui_import_text_dialog.h

io_graph_dialog.$(OBJEXT): ui_io_graph_dialog.h

interface_frame.$(OBJEXT): ui_interface_frame.h

interface_toolbar.$(OBJEXT): ui_interface_toolbar.h

layout_preferences_frame.$(OBJEXT): ui_layout_preferences_frame.h

lbm_lbtrm_transport_dialog.$(OBJEXT): ui_lbm_lbtrm_transport_dialog.h

lbm_lbtru_transport_dialog.$(OBJEXT): ui_lbm_lbtru_transport_dialog.h

lbm_stream_dialog.$(OBJEXT): ui_lbm_stream_dialog.h

lte_rlc_graph_dialog.$(OBJEXT): ui_lte_rlc_graph_dialog.h

main_welcome.$(OBJEXT): ui_main_welcome.h

main_window.$(OBJEXT): ui_main_window.h

main_window_preferences_frame.$(OBJEXT): ui_main_window_preferences_frame.h

main_window_slots.$(OBJEXT): ui_main_window.h

manage_interfaces_dialog.$(OBJEXT): ui_manage_interfaces_dialog.h

module_preferences_scroll_area.$(OBJEXT): ui_module_preferences_scroll_area.h

mtp3_summary_dialog.$(OBJEXT): ui_mtp3_summary_dialog.h

packet_comment_dialog.$(OBJEXT): ui_packet_comment_dialog.h

packet_dialog.$(OBJEXT): ui_packet_dialog.h

packet_format_group_box.$(OBJEXT): ui_packet_format_group_box.h

packet_range_group_box.$(OBJEXT): ui_packet_range_group_box.h

preference_editor_frame.$(OBJEXT): ui_preference_editor_frame.h

preferences_dialog.$(OBJEXT): ui_preferences_dialog.h

print_dialog.$(OBJEXT): ui_print_dialog.h

progress_frame.$(OBJEXT): ui_progress_frame.h

profile_dialog.$(OBJEXT): ui_profile_dialog.h

protocol_hierarchy_dialog.$(OBJEXT): ui_protocol_hierarchy_dialog.h

remote_capture_dialog.$(OBJEXT): ui_remote_capture_dialog.h

remote_settings_dialog.$(OBJEXT): ui_remote_settings_dialog.h

resolved_addresses_dialog.$(OBJEXT): ui_resolved_addresses_dialog.h

rtp_analysis_dialog.$(OBJEXT): ui_rtp_analysis_dialog.h

rtp_player_dialog.$(OBJEXT): ui_rtp_player_dialog.h

rtp_stream_dialog.$(OBJEXT): ui_rtp_stream_dialog.h

search_frame.$(OBJEXT): ui_search_frame.h

sequence_dialog.$(OBJEXT): ui_sequence_dialog.h

sctp_all_assocs_dialog.$(OBJEXT): ui_sctp_all_assocs_dialog.h

sctp_assoc_analyse_dialog.$(OBJEXT): ui_sctp_assoc_analyse_dialog.h

sctp_chunk_statistics_dialog.$(OBJEXT): ui_sctp_chunk_statistics_dialog.h

sctp_graph_dialog.$(OBJEXT): ui_sctp_graph_dialog.h

sctp_graph_arwnd_dialog.$(OBJEXT): ui_sctp_graph_arwnd_dialog.h

sctp_graph_byte_dialog.$(OBJEXT): ui_sctp_graph_byte_dialog.h

show_packet_bytes_dialog.$(OBJEXT): ui_show_packet_bytes_dialog.h

splash_overlay.$(OBJEXT): ui_splash_overlay.h

supported_protocols_dialog.$(OBJEXT): ui_supported_protocols_dialog.h

tap_parameter_dialog.$(OBJEXT): ui_tap_parameter_dialog.h

tcp_stream_dialog.$(OBJEXT): ui_tcp_stream_dialog.h

time_shift_dialog.$(OBJEXT): ui_time_shift_dialog.h

traffic_table_dialog.$(OBJEXT): ui_traffic_table_dialog.h

uat_dialog.$(OBJEXT): ui_uat_dialog.h

uat_frame.$(OBJEXT): ui_uat_frame.h

voip_calls_dialog.$(OBJEXT): ui_voip_calls_dialog.h

wireless_frame.$(OBJEXT): ui_wireless_frame.h

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

#checkapi: checkapi-base checkapi-todo

EXTRA_DIST = \
	$(GENERATOR_FILES)		\
	$(UI_FILES)			\
	$(QRC_FILES)			\
	$(TS_FILES)			\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	i18n.qrc.in			\
	Makefile_custom.common		\
	gpl-template.txt
