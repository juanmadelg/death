import "pe"

rule win_trojan_Qbot 
{
    meta:
      author = "Juanma"
      description = "Detects Qbot/Qakbot"
      reference = "https://bazaar.abuse.ch/sample/6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59/"
      date = "9/16/2025"
      hash = "6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59"
   strings:
      $s1 = "Tdk_threads_mutex" fullword ascii
      $s2 = "Tdk_window_process_updates" fullword ascii
      $s3 = "Tdk_window_process_all_updates" fullword ascii
      $s4 = "Tdk_spawn_command_line_on_screen" fullword ascii
      $s5 = "Tdk_utf8_to_string_target" fullword ascii
      $s6 = "gdk_pango_renderer_set_drawable() and gdk_pango_renderer_set_drawable()must be used to set the target drawable and GC before usi" ascii
      $s7 = "Tdk_drag_context_list_targets" fullword ascii
      $s8 = "Tdk_win32_selection_add_targets" fullword ascii
      $s9 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s10 = "Tdk_spawn_on_screen_with_pipes" fullword ascii
      $s11 = "Tdk_keymap_get_type" fullword ascii
   condition:
      pe.is_pe and
      filesize < 2000KB and
      all of ($s*)
}
