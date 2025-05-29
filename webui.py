import pdb
import logging

from dotenv import load_dotenv

load_dotenv()
import os
import glob
import asyncio
import argparse
# import os # Duplicate import removed

logger = logging.getLogger(__name__)

import gradio as gr

from browser_use.agent.service import Agent
# from playwright.async_api import async_playwright # Imported again later, keep one
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.browser.context import (
    BrowserContextConfig as OrgBrowserContextConfig, # Renamed to avoid clash
    BrowserContextWindowSize,
)
from langchain_ollama import ChatOllama
from playwright.async_api import async_playwright # Keep this one
from src.utils.agent_state import AgentState

from src.utils import utils
from src.agent.custom_agent import CustomAgent
from src.browser.custom_browser import CustomBrowser
from src.agent.custom_prompts import CustomSystemPrompt, CustomAgentMessagePrompt
# Use the renamed original BrowserContextConfig for the custom context if it's different
# If CustomBrowserContext expects the original, this is fine.
# If it expects its own version, it should be named differently.
# Assuming src.browser.custom_context.BrowserContextConfig is intentional and different.
from src.browser.custom_context import BrowserContextConfig as CustomBrowserContextConfigInternal
from src.browser.custom_context import CustomBrowserContext # Assuming this uses CustomBrowserContextConfigInternal
from src.controller.custom_controller import CustomController
from gradio.themes import Citrus, Default, Glass, Monochrome, Ocean, Origin, Soft, Base
from src.utils.default_config_settings import default_config, load_config_from_file, save_config_to_file, save_current_config, update_ui_from_config
from src.utils.utils import update_model_dropdown, get_latest_files, capture_screenshot

# Import network diagnostic skills
from network_diagnostic_skills import (
    NetworkDiagnosticSkill,
    DNSLookupSkill,
    PortScannerSkill,
    NetworkInterfaceSkill,
    BandwidthTestSkill,
    PacketSnifferSkill,
    ARPScanSkill,
    TCPConnectionTestSkill,
    LatencyMonitorSkill,
    RouteTableSkill,
)


# Global variables for persistence
_global_browser = None
_global_browser_context = None

# Create the global agent state instance
_global_agent_state = AgentState()

# Instantiate network diagnostic skills
network_diagnostic_tool = NetworkDiagnosticSkill()
dns_lookup_tool = DNSLookupSkill()
port_scanner_tool = PortScannerSkill()
interface_info_tool = NetworkInterfaceSkill()
bandwidth_test_tool = BandwidthTestSkill()
packet_sniffer_tool = PacketSnifferSkill()
arp_scan_tool = ARPScanSkill()
tcp_test_tool = TCPConnectionTestSkill()
latency_monitor_tool = LatencyMonitorSkill()
route_table_tool = RouteTableSkill()


# Define callback functions for network tools
def ping_skill_webui(target_ip, packet_size, count, timeout):
    return network_diagnostic_tool.ping(target_ip, int(packet_size), int(count), int(timeout))

def traceroute_skill_webui(target_ip, max_hops, packet_size):
    return network_diagnostic_tool.traceroute(target_ip, int(max_hops), int(packet_size))

def dns_lookup_skill_webui(domain, record_type, dns_server):
    return dns_lookup_tool.lookup(domain, record_type, dns_server)

def port_scan_skill_webui(target_ip, start_port, end_port):
    return port_scanner_tool.scan(target_ip, int(start_port), int(end_port))

def interface_info_skill_webui():
    info = interface_info_tool.get_info()
    if isinstance(info, dict):
        output_str = ""
        for iface, details_list in info.items():
            output_str += f"Interface: {iface}\n"
            for details in details_list:
                output_str += f"  Family: {details.get('family', 'N/A')}\n"
                output_str += f"  Address: {details.get('address', 'N/A')}\n"
                output_str += f"  Netmask: {details.get('netmask', 'N/A')}\n"
                output_str += f"  Broadcast: {details.get('broadcast', 'N/A')}\n"
            output_str += "\n"
        return output_str.strip()
    return str(info)

def bandwidth_test_skill_webui(download_url, upload_url):
    return bandwidth_test_tool.test(download_url, upload_url)

def packet_sniffer_skill_webui(filter_expr, count):
    return packet_sniffer_tool.sniff(filter_expr, int(count))

def arp_scan_skill_webui(ip_range):
    clients = arp_scan_tool.scan(ip_range)
    if isinstance(clients, list):
        if not clients:
            return "No devices found."
        output_str = "ARP Scan Results:\n"
        for client in clients:
            output_str += f"  IP: {client.get('ip', 'N/A')}, MAC: {client.get('mac', 'N/A')}\n"
        return output_str.strip()
    return str(clients)

def tcp_test_skill_webui(host, port, timeout):
    return tcp_test_tool.test(host, int(port), int(timeout))

def latency_monitor_skill_webui(target_ip, interval, duration):
    results = latency_monitor_tool.monitor(target_ip, int(interval), int(duration))
    return "\n".join(results)

def route_table_skill_webui():
    routes = route_table_tool.get_routes()
    output = [] 
    if routes and isinstance(routes[0], dict) and 'error' in routes[0]:
        return routes[0]['error']
    if not routes or (isinstance(routes[0], dict) and routes[0].get('status')):
        return routes[0].get('status', "No routes found or failed to parse.")

    for route in routes:
        output.append(f"Destination: {route.get('destination', 'N/A')}")
        output.append(f"  Netmask:   {route.get('netmask', 'N/A')}")
        output.append(f"  Gateway:   {route.get('gateway', 'N/A')}")
        output.append(f"  Interface: {route.get('interface', 'N/A')}")
        output.append("-" * 20) 
    return "\n".join(output)


async def stop_agent():
    """Request the agent to stop and update UI with enhanced feedback"""
    global _global_agent_state 

    try:
        _global_agent_state.request_stop()
        message = "Stop requested - the agent will halt at the next safe point"
        logger.info(f"🛑 {message}")
        return (
            message,                                       
            gr.update(value="Stopping...", interactive=False), 
            gr.update(interactive=False),                     
        )
    except Exception as e:
        error_msg = f"Error during stop: {str(e)}"
        logger.error(error_msg)
        return (
            error_msg,
            gr.update(value="Stop", interactive=True),
            gr.update(interactive=True)
        )
        
async def stop_research_agent():
    """Request the agent to stop and update UI with enhanced feedback for research agent"""
    global _global_agent_state 

    try:
        _global_agent_state.request_stop()
        message = "Stop requested - the research agent will halt at the next safe point"
        logger.info(f"🛑 {message}") 
        return (
            gr.update(value="Stopping...", interactive=False), 
            gr.update(interactive=False),                     
        )
    except Exception as e:
        error_msg = f"Error during research stop: {str(e)}"
        logger.error(error_msg)
        return (
            gr.update(value="Stop", interactive=True), 
            gr.update(interactive=True)               
        )

async def run_browser_agent(
        agent_type, # Can be "org", "custom", or "pen_test"
        llm_provider,
        llm_model_name,
        llm_temperature,
        llm_base_url,
        llm_api_key,
        use_own_browser,
        keep_browser_open,
        headless,
        disable_security,
        window_w,
        window_h,
        save_recording_path,
        save_agent_history_path,
        save_trace_path,
        enable_recording,
        task, # For "org" and "custom" agents
        add_infos, # For "custom" agent
        max_steps,
        use_vision,
        max_actions_per_step,
        tool_calling_method,
        # <<< BEGIN MODIFICATION: Add pen_test specific params >>>
        pen_test_target_url=None,
        pen_test_selected_tests=None
        # <<< END MODIFICATION >>>
):
    global _global_agent_state
    _global_agent_state.clear_stop() 

    try:
        if not enable_recording and agent_type != "pen_test": # Pen test might not need recording by default
            save_recording_path = None

        if save_recording_path:
            os.makedirs(save_recording_path, exist_ok=True)
        if save_agent_history_path: 
            os.makedirs(save_agent_history_path, exist_ok=True)
        if save_trace_path: 
            os.makedirs(save_trace_path, exist_ok=True)

        existing_videos = set()
        if save_recording_path and agent_type != "pen_test":
            existing_videos = set(
                glob.glob(os.path.join(save_recording_path, "*.[mM][pP]4"))
                + glob.glob(os.path.join(save_recording_path, "*.[wW][eE][bB][mM]"))
            )

        llm = utils.get_llm_model(
            provider=llm_provider,
            model_name=llm_model_name,
            temperature=llm_temperature,
            base_url=llm_base_url,
            api_key=llm_api_key,
        )

        # <<< BEGIN MODIFICATION: Handle "pen_test" agent type >>>
        if agent_type == "pen_test":
            # For pen_test, headless is True by default, no recording/trace needed for the report
            # The 'task' for the LLM will be constructed within execute_web_pen_test
            final_result, errors, model_actions, model_thoughts, trace_file, history_file = await execute_web_pen_test(
                llm=llm,
                target_url=pen_test_target_url,
                selected_tests=pen_test_selected_tests,
                use_own_browser=use_own_browser, # Pass relevant browser settings
                keep_browser_open=keep_browser_open,
                disable_security=disable_security,
                window_w=window_w,
                window_h=window_h,
                agent_state=_global_agent_state # Pass agent state for potential stop requests
            )
            latest_video = None # No video for pen test report
        # <<< END MODIFICATION >>>
        elif agent_type == "org":
            final_result, errors, model_actions, model_thoughts, trace_file, history_file = await run_org_agent(
                llm=llm,
                use_own_browser=use_own_browser,
                keep_browser_open=keep_browser_open,
                headless=headless,
                disable_security=disable_security,
                window_w=window_w,
                window_h=window_h,
                save_recording_path=save_recording_path,
                save_agent_history_path=save_agent_history_path,
                save_trace_path=save_trace_path,
                task=task,
                max_steps=max_steps,
                use_vision=use_vision,
                max_actions_per_step=max_actions_per_step,
                tool_calling_method=tool_calling_method
            )
        elif agent_type == "custom":
            final_result, errors, model_actions, model_thoughts, trace_file, history_file = await run_custom_agent(
                llm=llm,
                use_own_browser=use_own_browser,
                keep_browser_open=keep_browser_open,
                headless=headless,
                disable_security=disable_security,
                window_w=window_w,
                window_h=window_h,
                save_recording_path=save_recording_path,
                save_agent_history_path=save_agent_history_path,
                save_trace_path=save_trace_path,
                task=task,
                add_infos=add_infos,
                max_steps=max_steps,
                use_vision=use_vision,
                max_actions_per_step=max_actions_per_step,
                tool_calling_method=tool_calling_method
            )
        else:
            raise ValueError(f"Invalid agent type: {agent_type}")

        latest_video = None
        if save_recording_path and agent_type != "pen_test":
            all_videos = set(
                glob.glob(os.path.join(save_recording_path, "*.[mM][pP]4"))
                + glob.glob(os.path.join(save_recording_path, "*.[wW][eE][bB][mM]"))
            )
            new_videos = all_videos - existing_videos
            if new_videos:
                latest_video = max(new_videos, key=os.path.getctime)

        return (
            final_result,
            errors,
            model_actions,
            model_thoughts,
            latest_video,
            trace_file, 
            history_file, 
            gr.update(value="Stop", interactive=True), 
            gr.update(interactive=True)   
        )

    except gr.Error: 
        logger.error("A Gradio UI update error occurred.")
        raise 

    except Exception as e:
        import traceback
        logger.error(f"Exception in run_browser_agent: {e}\n{traceback.format_exc()}")
        errors_msg = str(e) + "\n" + traceback.format_exc()
        return (
            '',                                         
            errors_msg,                                 
            '',                                         
            '',                                         
            None,                                       
            None,                                       
            None,                                       
            gr.update(value="Stop", interactive=True), 
            gr.update(interactive=True)   
        )


async def run_org_agent(
        llm,
        use_own_browser,
        keep_browser_open,
        headless,
        disable_security,
        window_w,
        window_h,
        save_recording_path,
        save_agent_history_path,
        save_trace_path,
        task,
        max_steps,
        use_vision,
        max_actions_per_step,
        tool_calling_method
):
    global _global_browser, _global_browser_context, _global_agent_state
    trace_file_path = None 
    history_file_path = None 
    try:
        _global_agent_state.clear_stop()

        extra_chromium_args = [f"--window-size={int(window_w)},{int(window_h)}"]
        if use_own_browser:
            chrome_path = os.getenv("CHROME_PATH") 
            if chrome_path == "": chrome_path = None 
            chrome_user_data = os.getenv("CHROME_USER_DATA")
            if chrome_user_data:
                extra_chromium_args.append(f"--user-data-dir={chrome_user_data}")
        else:
            chrome_path = None
            
        if _global_browser is None:
            _global_browser = Browser(
                config=BrowserConfig(
                    headless=headless,
                    disable_security=disable_security,
                    chrome_instance_path=chrome_path,
                    extra_chromium_args=extra_chromium_args,
                )
            )

        if _global_browser_context is None:
            _global_browser_context = await _global_browser.new_context(
                config=OrgBrowserContextConfig( 
                    trace_path=save_trace_path if save_trace_path else None,
                    save_recording_path=save_recording_path if save_recording_path else None,
                    no_viewport=False, 
                    browser_window_size=BrowserContextWindowSize(
                        width=int(window_w), height=int(window_h)
                    ),
                )
            )
            
        agent = Agent(
            task=task,
            llm=llm,
            use_vision=use_vision,
            browser=_global_browser,
            browser_context=_global_browser_context,
            max_actions_per_step=max_actions_per_step,
            tool_calling_method=tool_calling_method,
            agent_state=_global_agent_state 
        )
        history = await agent.run(max_steps=max_steps)

        if save_agent_history_path:
            os.makedirs(save_agent_history_path, exist_ok=True)
            history_file_path = os.path.join(save_agent_history_path, f"{agent.agent_id}.json")
            agent.save_history(history_file_path)

        final_result = history.final_result()
        errors = history.errors()
        model_actions = history.model_actions()
        model_thoughts = history.model_thoughts()

        trace_files_dict = get_latest_files(save_trace_path)
        trace_file_path = trace_files_dict.get('.zip') if trace_files_dict else None

        return final_result, errors, model_actions, model_thoughts, trace_file_path, history_file_path
    except Exception as e:
        import traceback
        logger.error(f"Exception in run_org_agent: {e}\n{traceback.format_exc()}")
        errors_msg = str(e) + "\n" + traceback.format_exc()
        return '', errors_msg, '', '', None, None 
    finally:
        if not keep_browser_open:
            if _global_browser_context:
                await _global_browser_context.close()
                _global_browser_context = None
            if _global_browser:
                await _global_browser.close()
                _global_browser = None

async def run_custom_agent(
        llm,
        use_own_browser,
        keep_browser_open,
        headless,
        disable_security,
        window_w,
        window_h,
        save_recording_path,
        save_agent_history_path,
        save_trace_path,
        task,
        add_infos,
        max_steps,
        use_vision,
        max_actions_per_step,
        tool_calling_method
):
    global _global_browser, _global_browser_context, _global_agent_state
    trace_file_path = None 
    history_file_path = None 
    try:
        _global_agent_state.clear_stop()

        extra_chromium_args = [f"--window-size={int(window_w)},{int(window_h)}"]
        if use_own_browser:
            chrome_path = os.getenv("CHROME_PATH")
            if chrome_path == "": chrome_path = None
            chrome_user_data = os.getenv("CHROME_USER_DATA")
            if chrome_user_data:
                extra_chromium_args.append(f"--user-data-dir={chrome_user_data}")
        else:
            chrome_path = None

        controller = CustomController()

        if _global_browser is None:
            _global_browser = CustomBrowser( 
                config=BrowserConfig( 
                    headless=headless,
                    disable_security=disable_security,
                    chrome_instance_path=chrome_path,
                    extra_chromium_args=extra_chromium_args,
                )
            )
        if _global_browser_context is None:
            _global_browser_context = await _global_browser.new_context(
                config=CustomBrowserContextConfigInternal( 
                    trace_path=save_trace_path if save_trace_path else None,
                    save_recording_path=save_recording_path if save_recording_path else None,
                    no_viewport=False,
                    browser_window_size=BrowserContextWindowSize( 
                        width=int(window_w), height=int(window_h)
                    ),
                )
            )
            
        agent = CustomAgent(
            task=task,
            add_infos=add_infos,
            use_vision=use_vision,
            llm=llm,
            browser=_global_browser,
            browser_context=_global_browser_context,
            controller=controller,
            system_prompt_class=CustomSystemPrompt,
            agent_prompt_class=CustomAgentMessagePrompt,
            max_actions_per_step=max_actions_per_step,
            agent_state=_global_agent_state,
            tool_calling_method=tool_calling_method
        )
        history = await agent.run(max_steps=max_steps)

        if save_agent_history_path:
            os.makedirs(save_agent_history_path, exist_ok=True)
            history_file_path = os.path.join(save_agent_history_path, f"{agent.agent_id}.json")
            agent.save_history(history_file_path)

        final_result = history.final_result()
        errors = history.errors()
        model_actions = history.model_actions()
        model_thoughts = history.model_thoughts()

        trace_files_dict = get_latest_files(save_trace_path)
        trace_file_path = trace_files_dict.get('.zip') if trace_files_dict else None    

        return final_result, errors, model_actions, model_thoughts, trace_file_path, history_file_path
    except Exception as e:
        import traceback
        logger.error(f"Exception in run_custom_agent: {e}\n{traceback.format_exc()}")
        errors_msg = str(e) + "\n" + traceback.format_exc()
        return '', errors_msg, '', '', None, None 
    finally:
        if not keep_browser_open:
            if _global_browser_context:
                await _global_browser_context.close()
                _global_browser_context = None
            if _global_browser:
                await _global_browser.close()
                _global_browser = None

# <<< BEGIN MODIFICATION: Web Penetration Testing Agent Logic >>>
async def execute_web_pen_test(
    llm,
    target_url,
    selected_tests,
    use_own_browser, # To be consistent with other agents for browser setup
    keep_browser_open,
    disable_security,
    window_w,
    window_h,
    agent_state # For stop requests
):
    global _global_browser, _global_browser_context
    # This pen_test agent will run headlessly by default for analysis
    # It will manage its own browser instance or reuse global if keep_browser_open is True
    # and an existing compatible one is available.
    
    current_browser = None
    current_context = None
    is_new_browser_instance = False
    is_new_context_instance = False

    # Construct the detailed task for the LLM based on selected tests
    # This prompt needs to be carefully crafted for safety and effectiveness
    prompt_parts = [
        f"You are a web penetration testing assistant. Your goal is to analyze the website at {target_url} for potential vulnerabilities based on the selected tests. ",
        "You will use the provided browser to navigate and inspect the website. Adhere strictly to the test descriptions. Do NOT attempt to exploit vulnerabilities or perform disruptive actions. Your analysis should be descriptive.",
        "Report your findings clearly for each selected test.\n"
    ]

    if not selected_tests:
        return "No tests selected. Please choose at least one penetration testing category.", "", "", "", None, None

    if "Information Gathering" in selected_tests:
        prompt_parts.append(
            "\n--- Information Gathering ---\n"
            "1. Navigate to the target URL.\n"
            "2. Inspect the HTML source for comments, developer information, or clues about the technology stack.\n"
            "3. Check for `robots.txt` and `sitemap.xml` and summarize their content if found.\n"
            "4. Identify server type and any prominent technologies used (e.g., CMS, JavaScript libraries) based on headers and page content.\n"
            "5. Report your findings."
        )
    if "Security Headers" in selected_tests:
        prompt_parts.append(
            "\n--- Security Header Check ---\n"
            "1. Fetch the main page of the target URL.\n"
            "2. Inspect the HTTP response headers.\n"
            "3. Check for the presence and configuration of: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.\n"
            "4. Report on which headers are present, their values, any missing recommended headers, or potential misconfigurations."
        )
    if "XSS (Analyze & Describe)" in selected_tests:
        prompt_parts.append(
            "\n--- XSS Analysis (Describe Test Methodology) ---\n"
            "1. Identify potential input vectors on the main page (e.g., URL parameters, form fields accessible without login).\n"
            "2. For each vector, describe how you would test for reflected and stored XSS using a benign, non-breaking test string (e.g., 'XssTestString123').\n"
            "3. Explain what you would look for in the HTTP response or page content to indicate a potential XSS vulnerability (e.g., the test string being rendered unescaped).\n"
            "4. Do NOT attempt to inject actual `<script>` tags or exploit anything. This is an analytical exercise to describe the test process."
        )
    if "SQLi (Analyze & Describe)" in selected_tests:
        prompt_parts.append(
            "\n--- SQLi Analysis (Describe Test Methodology) ---\n"
            "1. Identify potential input vectors that might interact with a database (e.g., URL parameters like `id=1`, form fields).\n"
            "2. For each vector, describe how you would test for SQL injection by appending common SQL syntax (e.g., a single quote `'`, `OR 1=1`).\n"
            "3. Explain what changes in the HTTP response (e.g., errors, changes in content, different status codes) would indicate a potential SQL injection vulnerability.\n"
            "4. Do NOT attempt to execute data-modifying or disruptive SQL. This is an analytical exercise to describe the test process."
        )
    if "Exposed Paths/Files" in selected_tests:
        prompt_parts.append(
            "\n--- Exposed Paths/Files Check ---\n"
            "1. Attempt to navigate to common sensitive paths such as `/.git/config`, `/.env`, `/config.json`, `/wp-admin/` (if WordPress suspected), `/admin/`.\n"
            "2. Report if any of these paths return a 200 OK status or reveal sensitive information. Do not attempt to download large files or recursively explore directories found."
        )
    
    prompt_parts.append("\nCompile a consolidated report of your findings for all selected tests.")
    llm_task_description = "".join(prompt_parts)

    try:
        extra_chromium_args = [f"--window-size={int(window_w)},{int(window_h)}"]
        if use_own_browser:
            chrome_path = os.getenv("CHROME_PATH") 
            if chrome_path == "": chrome_path = None 
            chrome_user_data = os.getenv("CHROME_USER_DATA")
            if chrome_user_data:
                extra_chromium_args.append(f"--user-data-dir={chrome_user_data}")
        else:
            chrome_path = None

        # Browser and Context Management for Pen Test
        # This agent prefers its own isolated context or browser if not keeping open.
        if keep_browser_open and _global_browser and _global_browser_context:
            logger.info("Reusing global browser and context for pen test.")
            current_browser = _global_browser
            current_context = _global_browser_context
        else:
            logger.info("Creating new browser/context for pen test.")
            current_browser = Browser(
                config=BrowserConfig(
                    headless=True, # Pen test runs headlessly for analysis
                    disable_security=disable_security,
                    chrome_instance_path=chrome_path,
                    extra_chromium_args=extra_chromium_args,
                )
            )
            is_new_browser_instance = True
            current_context = await current_browser.new_context(
                 config=OrgBrowserContextConfig( # Using Org config for simplicity
                    no_viewport=False, 
                    browser_window_size=BrowserContextWindowSize(
                        width=int(window_w), height=int(window_h)
                    ),
                    # No recording or trace for pen test report by default
                )
            )
            is_new_context_instance = True


        # Use the standard Agent for interaction, with the constructed prompt
        # The 'task' for this agent is the detailed pen testing instruction set
        agent = Agent(
            task=llm_task_description, # This is the key instruction
            llm=llm,
            use_vision=False, # Vision not typically primary for this type of analysis
            browser=current_browser,
            browser_context=current_context,
            max_actions_per_step=5, # Allow a few actions per step for analysis
            tool_calling_method="auto", # Or as configured
            agent_state=agent_state 
        )
        
        # The agent will execute the steps described in the prompt.
        # This might involve multiple interactions with the browser.
        # Max_steps might need to be adjusted based on complexity.
        history = await agent.run(max_steps=max_steps if 'max_steps' in locals() else 20) # Default max_steps for pen test

        final_report = history.final_result() if history.final_result() else "No conclusive report generated by the LLM."
        errors_report = history.errors() if history.errors() else ""
        actions_report = history.model_actions() if history.model_actions() else "" # For debugging LLM's actions
        thoughts_report = history.model_thoughts() if history.model_thoughts() else "" # For debugging LLM's thoughts

        return final_report, errors_report, actions_report, thoughts_report, None, None # No trace/history files by default for this

    except Exception as e:
        import traceback
        logger.error(f"Exception in execute_web_pen_test: {e}\n{traceback.format_exc()}")
        return f"Error during web penetration test: {str(e)}", traceback.format_exc(), "", "", None, None
    finally:
        # Clean up browser if it was newly created for this test and not meant to be kept open
        if not keep_browser_open:
            if current_context and is_new_context_instance: # Close only if new and not global
                await current_context.close()
                if _global_browser_context == current_context: _global_browser_context = None
            if current_browser and is_new_browser_instance: # Close only if new and not global
                await current_browser.close()
                if _global_browser == current_browser: _global_browser = None
        elif is_new_context_instance and _global_browser_context is None: # if keep_browser_open but global was None
            _global_browser_context = current_context
        elif is_new_browser_instance and _global_browser is None: # if keep_browser_open but global was None
            _global_browser = current_browser


# <<< END MODIFICATION >>>


async def run_with_stream(
    agent_type,
    llm_provider,
    llm_model_name,
    llm_temperature,
    llm_base_url,
    llm_api_key,
    use_own_browser,
    keep_browser_open,
    headless,
    disable_security,
    window_w,
    window_h,
    save_recording_path,
    save_agent_history_path,
    save_trace_path,
    enable_recording,
    task,
    add_infos,
    max_steps,
    use_vision,
    max_actions_per_step,
    tool_calling_method,
    # <<< BEGIN MODIFICATION: Add pen_test specific params for run_with_stream >>>
    pen_test_target_url=None,
    pen_test_selected_tests=None
    # <<< END MODIFICATION >>>
):
    global _global_agent_state, _global_browser_context
    stream_vw = 80 
    stream_vh = int(stream_vw * int(window_h) // int(window_w)) if int(window_w) > 0 else int(stream_vw * 9/16) 

    # <<< BEGIN MODIFICATION: Handle pen_test type in run_with_stream >>>
    if agent_type == "pen_test":
        # Pen test runs headlessly and doesn't stream screenshots, it yields a final report.
        # We can show a "Testing in progress..." message.
        html_content_initial = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Web Penetration Test in progress...</h1></div>"
        # Yield initial state for UI updates (disabling buttons etc.)
        # The output structure should match what the UI expects (10 items for browser_view + agent results)
        yield [html_content_initial, "", "", "", "", None, None, None, gr.update(interactive=False), gr.update(interactive=False)]

        result = await run_browser_agent( # Call the modified run_browser_agent
            agent_type=agent_type,
            llm_provider=llm_provider,
            llm_model_name=llm_model_name,
            llm_temperature=llm_temperature,
            llm_base_url=llm_base_url,
            llm_api_key=llm_api_key,
            use_own_browser=use_own_browser,
            keep_browser_open=keep_browser_open,
            headless=True, # Pen test is headless for analysis
            disable_security=disable_security,
            window_w=window_w,
            window_h=window_h,
            save_recording_path=None, # No recording for pen test report
            save_agent_history_path=save_agent_history_path, # Can save history if desired
            save_trace_path=None, # No trace for pen test report
            enable_recording=False,
            task=None, # Not used directly for pen_test type here
            add_infos=None,
            max_steps=max_steps,
            use_vision=False, # Vision not primary for pen test analysis
            max_actions_per_step=max_actions_per_step,
            tool_calling_method=tool_calling_method,
            pen_test_target_url=pen_test_target_url,
            pen_test_selected_tests=pen_test_selected_tests
        )
        # Result: final_result, errors, model_actions, model_thoughts, latest_video, trace_file, history_file, stop_button_update, run_button_update
        # For pen_test, final_result is the report. Errors might contain execution errors.
        # model_actions/thoughts can be useful for debugging the LLM's process.
        html_content_final = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Web Penetration Test Complete. View report.</h1></div>"
        # Adapt the result to the 10-item yield structure.
        # The first item is browser_view, then the 7 agent result items, then 2 button updates.
        yield [html_content_final, result[0], result[1], result[2], result[3], None, None, result[6], result[7], result[8]]
        return # End of stream for pen_test
    # <<< END MODIFICATION >>>
    elif not headless: # Original logic for non-headless browser agent
        html_content_initial = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Using browser directly...</h1></div>"
        yield [html_content_initial, "", "", "", "", None, None, None, gr.update(interactive=False), gr.update(interactive=False)]

        result = await run_browser_agent(
            agent_type=agent_type,
            llm_provider=llm_provider,
            llm_model_name=llm_model_name,
            llm_temperature=llm_temperature,
            llm_base_url=llm_base_url,
            llm_api_key=llm_api_key,
            use_own_browser=use_own_browser,
            keep_browser_open=keep_browser_open,
            headless=headless, 
            disable_security=disable_security,
            window_w=window_w,
            window_h=window_h,
            save_recording_path=save_recording_path,
            save_agent_history_path=save_agent_history_path,
            save_trace_path=save_trace_path,
            enable_recording=enable_recording,
            task=task,
            add_infos=add_infos,
            max_steps=max_steps,
            use_vision=use_vision,
            max_actions_per_step=max_actions_per_step,
            tool_calling_method=tool_calling_method
            # No pen_test_target_url or pen_test_selected_tests for org/custom
        )
        html_content_final = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Task Complete. View results.</h1></div>"
        yield [html_content_final] + list(result)
    else: # Original logic for headless browser agent (streaming screenshots)
        try:
            _global_agent_state.clear_stop()
            agent_task = asyncio.create_task(
                run_browser_agent(
                    agent_type=agent_type,
                    llm_provider=llm_provider,
                    llm_model_name=llm_model_name,
                    llm_temperature=llm_temperature,
                    llm_base_url=llm_base_url,
                    llm_api_key=llm_api_key,
                    use_own_browser=use_own_browser,
                    keep_browser_open=keep_browser_open,
                    headless=headless, 
                    disable_security=disable_security,
                    window_w=window_w,
                    window_h=window_h,
                    save_recording_path=save_recording_path,
                    save_agent_history_path=save_agent_history_path,
                    save_trace_path=save_trace_path,
                    enable_recording=enable_recording,
                    task=task,
                    add_infos=add_infos,
                    max_steps=max_steps,
                    use_vision=use_vision,
                    max_actions_per_step=max_actions_per_step,
                    tool_calling_method=tool_calling_method
                )
            )

            html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Initializing headless browser...</h1></div>"
            final_result, errors_output_val, model_actions_val, model_thoughts_val = "", "", "", ""
            latest_video_val, trace_file_val, history_file_val = None, None, None
            stop_button_update = gr.update(value="Stop", interactive=True)
            run_button_update = gr.update(interactive=True)

            while not agent_task.done():
                if _global_agent_state and _global_agent_state.is_stop_requested():
                    logger.info("Stop requested, breaking stream loop.")
                    html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Agent stopping...</h1></div>"
                    stop_button_update = gr.update(value="Stopping...", interactive=False)
                    run_button_update = gr.update(interactive=False) 
                    yield [html_content, final_result, errors_output_val, model_actions_val, model_thoughts_val, latest_video_val, trace_file_val, history_file_val, stop_button_update, run_button_update]
                    break 

                try:
                    if _global_browser_context and headless: 
                        encoded_screenshot = await capture_screenshot(_global_browser_context)
                        if encoded_screenshot:
                            html_content = f'<img src="data:image/jpeg;base64,{encoded_screenshot}" style="width:{stream_vw}vw; height:{stream_vh}vh; object-fit:contain; border:1px solid #ccc;">'
                        else: 
                            if not html_content.startswith("<img"): 
                                html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Waiting for browser page...</h1></div>"
                    elif not headless: 
                         html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Browser running directly (not headless)...</h1></div>"
                    else: 
                         html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Waiting for browser session...</h1></div>"

                except Exception as e:
                    logger.warning(f"Screenshot capture/display error: {e}")
                    if not html_content.startswith("<img"):
                        html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Error updating view...</h1></div>"
                
                yield [
                    html_content,
                    final_result, errors_output_val, model_actions_val, model_thoughts_val,
                    latest_video_val, trace_file_val, history_file_val,
                    stop_button_update, run_button_update
                ]
                await asyncio.sleep(0.1) 

            try:
                (final_result, errors_output_val, model_actions_val, model_thoughts_val,
                 latest_video_val, trace_file_val, history_file_val,
                 stop_button_update, run_button_update) = await agent_task

                if _global_browser_context and headless and not (_global_agent_state and _global_agent_state.is_stop_requested()):
                    encoded_screenshot = await capture_screenshot(_global_browser_context)
                    if encoded_screenshot:
                        html_content = f'<img src="data:image/jpeg;base64,{encoded_screenshot}" style="width:{stream_vw}vw; height:{stream_vh}vh; object-fit:contain; border:1px solid #ccc;">'
                    else:
                        html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Task ended.</h1></div>"
                elif _global_agent_state and _global_agent_state.is_stop_requested():
                    html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Agent Stopped.</h1></div>"
                else:
                    html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Task ended.</h1></div>"

            except asyncio.CancelledError:
                logger.info("Agent task was cancelled.")
                html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Task Cancelled.</h1></div>"
                errors_output_val = "Task cancelled by user or system."
                stop_button_update = gr.update(value="Stop", interactive=True) 
                run_button_update = gr.update(interactive=True) 

            except Exception as e: 
                import traceback
                logger.error(f"Error in agent_task or retrieving its result: {e}\n{traceback.format_exc()}")
                html_content = f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Agent Error</h1></div>"
                errors_output_val = f"Agent execution error: {str(e)}\n{traceback.format_exc()}"
                stop_button_update = gr.update(value="Stop", interactive=True)
                run_button_update = gr.update(interactive=True)

            yield [
                html_content,
                final_result, errors_output_val, model_actions_val, model_thoughts_val,
                latest_video_val, trace_file_val, history_file_val,
                stop_button_update, run_button_update
            ]

        except Exception as e: 
            import traceback
            logger.error(f"General error in run_with_stream (headless): {e}\n{traceback.format_exc()}")
            yield [
                f"<div style='width:{stream_vw}vw; height:{stream_vh}vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Stream Error</h1></div>",
                "", f"Error: {str(e)}\n{traceback.format_exc()}", "", "",
                None, None, None,
                gr.update(value="Stop", interactive=True),
                gr.update(interactive=True)
            ]

theme_map = {
    "Default": Default(), "Soft": Soft(), "Monochrome": Monochrome(),
    "Glass": Glass(), "Origin": Origin(), "Citrus": Citrus(),
    "Ocean": Ocean(), "Base": Base(),
}

async def close_global_browser():
    global _global_browser, _global_browser_context
    logger.info("Attempting to close global browser and context due to config change.")
    if _global_browser_context:
        try:
            await _global_browser_context.close()
            logger.info("Global browser context closed.")
        except Exception as e:
            logger.error(f"Error closing global browser context: {e}")
        finally:
            _global_browser_context = None

    if _global_browser:
        try:
            await _global_browser.close()
            logger.info("Global browser closed.")
        except Exception as e:
            logger.error(f"Error closing global browser: {e}")
        finally:
            _global_browser = None
        
async def run_deep_search(
    research_task, 
    max_search_iteration_input, 
    max_query_per_iter_input, 
    llm_provider, 
    llm_model_name, 
    llm_temperature, 
    llm_base_url, 
    llm_api_key, 
    use_vision, 
    use_own_browser, 
    headless,        
    tool_calling_method, 
    login=None 
):
    from src.utils.deep_research import deep_research 
    global _global_agent_state

    _global_agent_state.clear_stop()
    
    llm = utils.get_llm_model(
        provider=llm_provider,
        model_name=llm_model_name,
        temperature=llm_temperature,
        base_url=llm_base_url,
        api_key=llm_api_key
    )
                                                                       
    markdown_content, file_path = await deep_research(
        research_task, 
        llm, 
        _global_agent_state,
        max_search_iterations=int(max_search_iteration_input),
        max_query_num=int(max_query_per_iter_input),
        use_vision=use_vision, 
        headless=headless,     
        use_own_browser=use_own_browser 
    )
    
    return markdown_content, file_path, gr.update(value="Stop", interactive=True), gr.update(interactive=True) 
    

def create_ui(config, theme_name="Ocean"):
    css = """
    .gradio-container { max-width: 1200px !important; margin: auto !important; padding-top: 20px !important; }
    .header-text { text-align: center; margin-bottom: 30px; }
    .theme-section { margin-bottom: 20px; padding: 15px; border-radius: 10px; }
    .disclaimer { color: orange; font-weight: bold; margin-bottom: 10px; }
    """ # Added disclaimer style

    with gr.Blocks(title="Browser Use WebUI", theme=theme_map.get(theme_name, Ocean()), css=css) as demo:
        gr.Markdown("# 🌐 Browser Use WebUI\n### Control your browser with AI assistance", elem_classes=["header-text"])

        with gr.Tabs() as tabs:
            with gr.TabItem("⚙️ Agent Settings", id=1):
                with gr.Group():
                    agent_type = gr.Radio(["org", "custom"], label="Agent Type", value=config.get('agent_type', 'custom'), info="Select agent type") # pen_test type is handled internally now
                    with gr.Column(): 
                        max_steps = gr.Slider(1, 200, value=config.get('max_steps', 50), step=1, label="Max Run Steps", info="Max steps per agent run")
                        max_actions_per_step = gr.Slider(1, 20, value=config.get('max_actions_per_step', 3), step=1, label="Max Actions per Step", info="Max actions per LLM call")
                    with gr.Column():
                        use_vision = gr.Checkbox(label="Use Vision", value=config.get('use_vision', True), info="Enable visual processing")
                        tool_calling_method = gr.Dropdown(
                            label="Tool Calling Method", value=config.get('tool_calling_method', 'auto'),
                            interactive=True, allow_custom_value=False, 
                            choices=["auto", "json_schema", "function_calling"], 
                            info="Method for LLM tool invocation (if supported)",
                        )

            with gr.TabItem("🔧 LLM Configuration", id=2):
                with gr.Group():
                    llm_provider = gr.Dropdown(
                        choices=list(utils.model_names.keys()), label="LLM Provider",
                        value=config.get('llm_provider', 'openai'), info="Select LLM provider"
                    )
                    llm_model_name = gr.Dropdown(
                        label="Model Name", choices=utils.model_names.get(config.get('llm_provider', 'openai'), []),
                        value=config.get('llm_model_name', 'gpt-4-turbo'), interactive=True, allow_custom_value=True,
                        info="Select or type model name"
                    )
                    llm_temperature = gr.Slider(0.0, 2.0, value=config.get('llm_temperature', 0.0), step=0.1, label="Temperature", info="Model output randomness")
                    with gr.Row():
                        llm_base_url = gr.Textbox(label="Base URL (Optional)", value=config.get('llm_base_url', ''), info="API endpoint if not default")
                        llm_api_key = gr.Textbox(label="API Key (Optional)", type="password", value=config.get('llm_api_key', ''), info="API key (uses .env if blank)")

            with gr.TabItem("🌐 Browser Settings", id=3):
                with gr.Group():
                    with gr.Row():
                        use_own_browser = gr.Checkbox(label="Use Own Browser", value=config.get('use_own_browser', False), info="Use local Chrome profile (CHROME_PATH, CHROME_USER_DATA in .env)")
                        keep_browser_open = gr.Checkbox(label="Keep Browser Open", value=config.get('keep_browser_open', False), info="Persist browser between agent runs")
                        headless = gr.Checkbox(label="Headless Mode (for Browser Agent)", value=config.get('headless', True), info="Run browser without GUI (Web Pen Test is always headless for analysis)")
                        disable_security = gr.Checkbox(label="Disable Security (Careful!)", value=config.get('disable_security', False), info="Disables web security like CORS (use with caution)")
                        enable_recording = gr.Checkbox(label="Enable Recording (for Browser Agent)", value=config.get('enable_recording', False), info="Save video of browser session (not for Web Pen Test)")
                    with gr.Row():
                        window_w = gr.Number(label="Window Width", value=config.get('window_w', 1920), precision=0, info="Browser window width")
                        window_h = gr.Number(label="Window Height", value=config.get('window_h', 1080), precision=0, info="Browser window height")
                    save_recording_path = gr.Textbox(label="Recording Path", placeholder="./tmp/record_videos", value=config.get('save_recording_path', './tmp/record_videos'), info="Path to save recordings", interactive=config.get('enable_recording', False))
                    save_trace_path = gr.Textbox(label="Trace Path", placeholder="./tmp/traces", value=config.get('save_trace_path', './tmp/traces'), info="Path to save Playwright traces")
                    save_agent_history_path = gr.Textbox(label="Agent History Path", placeholder="./tmp/agent_history", value=config.get('save_agent_history_path', './tmp/agent_history'), info="Path to save agent interaction history")

            with gr.TabItem("🤖 Run Agent", id=4):
                task = gr.Textbox(label="Task Description", lines=4, placeholder="Enter your task here...", value=config.get('task', 'Go to google.com and search for "current AI trends"'), info="What the agent should do")
                add_infos = gr.Textbox(label="Additional Information (Optional)", lines=3, placeholder="E.g., login credentials, specific URLs, context...", info="Hints for the LLM")
                with gr.Row():
                    run_button = gr.Button("▶️ Run Agent", variant="primary", scale=2)
                    stop_button = gr.Button("⏹️ Stop Agent", variant="stop", scale=1) 
                with gr.Row(): 
                    browser_view = gr.HTML(value="<div style='width:80vw; height:50vh; display:flex; align-items:center; justify-content:center; border:1px solid #ccc;'><h1>Waiting for browser session...</h1></div>", label="Live Browser View (Headless Only)")
            
            with gr.TabItem("🧐 Deep Research", id=5):
                research_task_input = gr.Textbox(label="Research Task", lines=5, value=config.get('research_task',"Compose a report on the use of Reinforcement Learning for training Large Language Models..."))
                with gr.Row():
                    max_search_iteration_input = gr.Number(label="Max Search Iterations", value=config.get('max_search_iterations',3), precision=0)
                    max_query_per_iter_input = gr.Number(label="Max Queries per Iteration", value=config.get('max_queries_per_iteration',1), precision=0)
                with gr.Row():
                    research_button = gr.Button("▶️ Run Deep Research", variant="primary", scale=2)
                    stop_research_button = gr.Button("⏹️ Stop Research", variant="stop", scale=1) 
                markdown_output_display = gr.Markdown(label="Research Report")
                markdown_download = gr.File(label="Download Research Report (Markdown)")


            with gr.TabItem("📊 Agent Results", id=6): 
                with gr.Group():
                    recording_display = gr.Video(label="Latest Recording")
                    gr.Markdown("### Agent Execution Details")
                    with gr.Row():
                        final_result_output = gr.Textbox(label="Final Result / Report", lines=5, show_label=True, interactive=False) # Increased lines for reports
                        errors_output = gr.Textbox(label="Errors/Logs", lines=5, show_label=True, interactive=False) # Increased lines
                    with gr.Row():
                        model_actions_output = gr.Textbox(label="Model Actions (Debug)", lines=5, show_label=True, interactive=False)
                        model_thoughts_output = gr.Textbox(label="Model Thoughts (Debug)", lines=5, show_label=True, interactive=False)
                    with gr.Row():
                        trace_file = gr.File(label="Download Playwright Trace")
                        agent_history_file = gr.File(label="Download Agent History")
            
            # <<< BEGIN MODIFICATION: Web Penetration Testing Tab >>>
            with gr.TabItem("🛡️ Web Penetration Testing", id=10): # New Tab ID
                gr.Markdown(
                    "## LLM-Assisted Web Application Analysis\n"
                    "<p class='disclaimer'>⚠️ **Disclaimer:** This tool is for educational and authorized testing purposes only. "
                    "Ensure you have explicit, written permission from the website owner before conducting any tests. "
                    "Unauthorized testing is illegal and unethical. Use responsibly.</p>",
                    elem_classes=["disclaimer"] # For custom styling if needed
                )
                with gr.Group():
                    pen_test_target_url_input = gr.Textbox(label="Target URL", placeholder="e.g., https://example.com", info="The full URL of the website to test.")
                    pen_test_types_checkboxes = gr.CheckboxGroup(
                        label="Select Test Categories",
                        choices=[
                            "Information Gathering", 
                            "Security Headers", 
                            "XSS (Analyze & Describe)", 
                            "SQLi (Analyze & Describe)", 
                            "Exposed Paths/Files"
                        ],
                        value=["Information Gathering", "Security Headers"], # Default selection
                        info="Choose the types of analysis to perform."
                    )
                    pen_test_run_button = gr.Button("🚀 Start Web Test", variant="primary")
                    pen_test_stop_button = gr.Button("⏹️ Stop Web Test", variant="stop") # For consistency
                
                pen_test_report_output = gr.Textbox(label="Web Test Report & Logs", lines=20, interactive=False, placeholder="LLM analysis and findings will appear here...")

                # Event handler for the Web Pen Test button
                pen_test_run_button.click(
                    fn=run_with_stream, # Reusing run_with_stream, it will call run_browser_agent with agent_type="pen_test"
                    inputs=[
                        gr.Textbox(value="pen_test", visible=False), # agent_type
                        llm_provider, llm_model_name, llm_temperature, llm_base_url, llm_api_key,
                        use_own_browser, keep_browser_open, 
                        gr.Checkbox(value=True, visible=False), # headless (always true for pen_test analysis)
                        disable_security, window_w, window_h,
                        gr.Textbox(value=None, visible=False), # save_recording_path
                        save_agent_history_path, # Can still save history
                        gr.Textbox(value=None, visible=False), # save_trace_path
                        gr.Checkbox(value=False, visible=False), # enable_recording
                        gr.Textbox(value=None, visible=False), # task (not used directly)
                        gr.Textbox(value=None, visible=False), # add_infos (not used directly)
                        max_steps, # Max steps for the LLM's analysis
                        gr.Checkbox(value=False, visible=False), # use_vision (false for pen_test)
                        max_actions_per_step, 
                        tool_calling_method,
                        pen_test_target_url_input, # Specific to pen_test
                        pen_test_types_checkboxes  # Specific to pen_test
                    ],
                    outputs=[ # Matches the 10 outputs of run_with_stream
                        browser_view, # Will show "Testing in progress..." then "Complete"
                        pen_test_report_output, # Main report here
                        errors_output, # General errors from the run
                        model_actions_output, # LLM actions (for debug)
                        model_thoughts_output, # LLM thoughts (for debug)
                        recording_display, # Will be None
                        trace_file, # Will be None
                        agent_history_file, # Can be populated
                        pen_test_stop_button, # Connect to the specific stop button
                        pen_test_run_button
                    ]
                )
                pen_test_stop_button.click( # Connect the stop button
                    fn=stop_agent, # Generic stop agent should work if agent_state is managed
                    inputs=[],
                    outputs=[errors_output, pen_test_stop_button, pen_test_run_button]
                )

            # <<< END MODIFICATION >>>


            with gr.TabItem("🛠️ Network Tools", id=9): 
                gr.Markdown("## Network Diagnostic Suite")
                with gr.Tabs() as network_tool_tabs: 
                    with gr.TabItem("Ping"):
                        with gr.Row():
                            ping_target_ip_webui = gr.Textbox(label="Target IP", placeholder="e.g., 8.8.8.8 or google.com")
                            ping_packet_size_webui = gr.Number(label="Packet Size", value=56)
                            ping_count_webui = gr.Number(label="Count", value=4, precision=0)
                            ping_timeout_webui = gr.Number(label="Timeout (seconds)", value=1)
                        ping_output_webui = gr.Textbox(label="Ping Output", lines=10, interactive=False)
                        ping_button_webui = gr.Button("Ping")
                        ping_button_webui.click(
                            ping_skill_webui, 
                            inputs=[ping_target_ip_webui, ping_packet_size_webui, ping_count_webui, ping_timeout_webui], 
                            outputs=ping_output_webui
                        )

                    with gr.TabItem("Traceroute"):
                        with gr.Row():
                            traceroute_target_ip_webui = gr.Textbox(label="Target IP", placeholder="e.g., 8.8.8.8 or google.com")
                            traceroute_max_hops_webui = gr.Number(label="Max Hops", value=30, precision=0)
                            traceroute_packet_size_webui = gr.Number(label="Packet Size", value=40)
                        traceroute_output_webui = gr.Textbox(label="Traceroute Output", lines=10, interactive=False)
                        traceroute_button_webui = gr.Button("Traceroute")
                        traceroute_button_webui.click(
                            traceroute_skill_webui,
                            inputs=[traceroute_target_ip_webui, traceroute_max_hops_webui, traceroute_packet_size_webui],
                            outputs=traceroute_output_webui,
                        )

                    with gr.TabItem("DNS Lookup"):
                        with gr.Row():
                            dns_domain_webui = gr.Textbox(label="Domain", placeholder="e.g., google.com")
                            dns_record_type_webui = gr.Dropdown(
                                label="Record Type",
                                choices=["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV"],
                                value="A",
                            )
                            dns_server_webui = gr.Textbox(label="DNS Server", value="8.8.8.8", placeholder="e.g., 8.8.8.8")
                        dns_output_webui = gr.Textbox(label="DNS Output", lines=10, interactive=False)
                        dns_button_webui = gr.Button("Lookup")
                        dns_button_webui.click(
                            dns_lookup_skill_webui,
                            inputs=[dns_domain_webui, dns_record_type_webui, dns_server_webui],
                            outputs=dns_output_webui,
                        )

                    with gr.TabItem("Port Scanner"):
                        with gr.Row():
                            ps_target_ip_webui = gr.Textbox(label="Target IP", placeholder="e.g., scanme.nmap.org or an IP address")
                            ps_start_port_webui = gr.Number(label="Start Port", value=1, precision=0)
                            ps_end_port_webui = gr.Number(label="End Port", value=1024, precision=0)
                        port_scan_output_webui = gr.Textbox(label="Port Scan Output", lines=10, interactive=False)
                        port_scan_button_webui = gr.Button("Scan Ports")
                        port_scan_button_webui.click(
                            port_scan_skill_webui,
                            inputs=[ps_target_ip_webui, ps_start_port_webui, ps_end_port_webui],
                            outputs=port_scan_output_webui,
                        )

                    with gr.TabItem("Interface Info"):
                        interface_output_webui = gr.Textbox(label="Interface Info", lines=10, interactive=False)
                        interface_button_webui = gr.Button("Get Network Interface Info")
                        interface_button_webui.click(interface_info_skill_webui, inputs=[], outputs=interface_output_webui)

                    with gr.TabItem("Bandwidth Test"):
                        with gr.Row():
                            bw_download_url_webui = gr.Textbox(
                                label="Download URL",
                                value="http://speedtest.ftp.otenet.gr/files/test100Mb.db",
                            )
                            bw_upload_url_webui = gr.Textbox(label="Upload URL", value="http://httpbin.org/post")
                        bandwidth_output_webui = gr.Textbox(label="Bandwidth Test Output", lines=10, interactive=False)
                        bandwidth_button_webui = gr.Button("Test Bandwidth")
                        bandwidth_button_webui.click(
                            bandwidth_test_skill_webui,
                            inputs=[bw_download_url_webui, bw_upload_url_webui],
                            outputs=bandwidth_output_webui,
                        )

                    with gr.TabItem("Packet Sniffer"):
                        gr.Markdown("⚠️ **Warning:** Packet sniffing may require administrative/root privileges to run correctly.")
                        with gr.Row():
                            sniff_filter_webui = gr.Textbox(label="BPF Filter (optional)", value="", placeholder="e.g., 'tcp port 80'")
                            sniff_count_webui = gr.Number(label="Packet Count", value=10, precision=0)
                        packet_sniffer_output_webui = gr.Textbox(label="Captured Packets Summary", lines=10, interactive=False)
                        packet_sniffer_button_webui = gr.Button("Start Sniffing")
                        packet_sniffer_button_webui.click(
                            packet_sniffer_skill_webui, inputs=[sniff_filter_webui, sniff_count_webui], outputs=packet_sniffer_output_webui
                        )

                    with gr.TabItem("ARP Scan"):
                        gr.Markdown("⚠️ **Note:** ARP Scan is typically effective only on the local network segment.")
                        with gr.Row():
                            arp_ip_range_webui = gr.Textbox(label="IP Range (CIDR)", value="192.168.1.0/24", placeholder="e.g., 192.168.1.0/24")
                        arp_scan_output_webui = gr.Textbox(label="ARP Scan Output", lines=10, interactive=False)
                        arp_scan_button_webui = gr.Button("Scan Local Network (ARP)")
                        arp_scan_button_webui.click(
                            arp_scan_skill_webui, inputs=[arp_ip_range_webui], outputs=arp_scan_output_webui
                        )

                    with gr.TabItem("TCP Connection Test"):
                        with gr.Row():
                            tcp_host_webui = gr.Textbox(label="Target Host", placeholder="e.g., google.com or an IP address")
                            tcp_port_webui = gr.Number(label="Target Port", value=80, precision=0)
                            tcp_timeout_webui = gr.Number(label="Timeout (seconds)", value=5)
                        tcp_test_output_webui = gr.Textbox(label="TCP Test Output", lines=10, interactive=False)
                        tcp_test_button_webui = gr.Button("Test TCP Connection")
                        tcp_test_button_webui.click(
                            tcp_test_skill_webui, inputs=[tcp_host_webui, tcp_port_webui, tcp_timeout_webui], outputs=tcp_test_output_webui
                        )

                    with gr.TabItem("Latency Monitor"):
                        gr.Markdown("⚠️ **Note:** This will perform repeated pings. Ensure you have permission and be mindful of network load.")
                        with gr.Row():
                            lat_target_ip_webui = gr.Textbox(label="Target IP", placeholder="e.g., 8.8.8.8")
                            lat_interval_webui = gr.Number(label="Interval (seconds)", value=60, precision=0)
                            lat_duration_webui = gr.Number(label="Duration (seconds)", value=300, precision=0)
                        latency_output_webui = gr.Textbox(label="Latency Monitor Output", lines=10, interactive=False)
                        latency_button_webui = gr.Button("Start Latency Monitoring")
                        latency_button_webui.click(
                            latency_monitor_skill_webui,
                            inputs=[lat_target_ip_webui, lat_interval_webui, lat_duration_webui],
                            outputs=latency_output_webui,
                        )

                    with gr.TabItem("Route Table"):
                        route_table_output_webui = gr.Textbox(label="Route Table Output", lines=10, interactive=False)
                        route_table_button_webui = gr.Button("Get System Route Table")
                        route_table_button_webui.click(route_table_skill_webui, inputs=[], outputs=route_table_output_webui)


            with gr.TabItem("🎥 Recordings Gallery", id=7): 
                def list_recordings(path):
                    if not path or not os.path.exists(path): return []
                    recordings = glob.glob(os.path.join(path, "*.[mM][pP]4")) + \
                                 glob.glob(os.path.join(path, "*.[wW][eE][bB][mM]"))
                    recordings.sort(key=os.path.getmtime, reverse=True) 
                    return [(rec, os.path.basename(rec)) for rec in recordings]

                recordings_gallery = gr.Gallery(label="Session Recordings", value=list_recordings(config.get('save_recording_path')), columns=3, height="auto", object_fit="contain", type="filepath")
                refresh_button = gr.Button("🔄 Refresh Recordings", variant="secondary")
                refresh_button.click(fn=list_recordings, inputs=save_recording_path, outputs=recordings_gallery)
            
            with gr.TabItem("📁 Configuration Management", id=8): 
                with gr.Group():
                    config_file_input = gr.File(label="Load Config From .pkl File", file_types=[".pkl"], interactive=True)
                    load_config_button = gr.Button("Load Config", variant="secondary")
                    save_config_button = gr.Button("Save Current Config to default.pkl", variant="primary")
                    config_status = gr.Textbox(label="Status", lines=2, interactive=False)

                load_config_button.click(
                    fn=update_ui_from_config, inputs=[config_file_input],
                    outputs=[ 
                        agent_type, max_steps, max_actions_per_step, use_vision, tool_calling_method,
                        llm_provider, llm_model_name, llm_temperature, llm_base_url, llm_api_key,
                        use_own_browser, keep_browser_open, headless, disable_security, enable_recording,
                        window_w, window_h, save_recording_path, save_trace_path, save_agent_history_path,
                        task, config_status 
                    ]
                )
                save_config_button.click(
                    fn=save_current_config,
                    inputs=[ 
                        agent_type, max_steps, max_actions_per_step, use_vision, tool_calling_method,
                        llm_provider, llm_model_name, llm_temperature, llm_base_url, llm_api_key,
                        use_own_browser, keep_browser_open, headless, disable_security,
                        enable_recording, window_w, window_h, save_recording_path, save_trace_path,
                        save_agent_history_path, task, 
                    ],  
                    outputs=[config_status]
                )
        # Event handlers for Agent Results tab (moved outside the tab definition for clarity)
        stop_button.click(
            fn=stop_agent, inputs=[],
            outputs=[errors_output, stop_button, run_button] 
        )
        run_button.click(
            fn=run_with_stream, # This now handles agent_type="org" or "custom"
            inputs=[
                agent_type, # This will be 'org' or 'custom' from the radio button
                llm_provider, llm_model_name, llm_temperature, llm_base_url, llm_api_key,
                use_own_browser, keep_browser_open, headless, disable_security, window_w, window_h,
                save_recording_path, save_agent_history_path, save_trace_path,
                enable_recording, task, add_infos, max_steps, use_vision, max_actions_per_step, tool_calling_method,
                # pen_test_target_url and pen_test_selected_tests are None for this call
            ],
            outputs=[ 
                browser_view, final_result_output, errors_output, model_actions_output,
                model_thoughts_output, recording_display, trace_file, agent_history_file,
                stop_button, run_button
            ],
        )
        
        research_button.click(
            fn=run_deep_search,
            inputs=[ 
                research_task_input, max_search_iteration_input, max_query_per_iter_input, 
                llm_provider, llm_model_name, llm_temperature, llm_base_url, llm_api_key, 
                use_vision, use_own_browser, headless, tool_calling_method 
            ],
            outputs=[markdown_output_display, markdown_download, stop_research_button, research_button]
        )
        stop_research_button.click(
            fn=stop_research_agent, inputs=[],
            outputs=[stop_research_button, research_button], 
        )


        llm_provider.change(
            fn=update_model_dropdown, 
            inputs=[llm_provider, llm_api_key, llm_base_url], 
            outputs=llm_model_name
        )
        enable_recording.change(lambda enabled: gr.update(interactive=enabled), inputs=enable_recording, outputs=save_recording_path)
        
        use_own_browser.change(fn=close_global_browser) 
        keep_browser_open.change(fn=lambda kbo: asyncio.ensure_future(close_global_browser()) if not kbo else None, inputs=[keep_browser_open])


    return demo

def main():
    parser = argparse.ArgumentParser(description="Gradio UI for Browser Agent")
    parser.add_argument("--ip", type=str, default=os.getenv("GRADIO_SERVER_NAME", "127.0.0.1"), help="IP address to bind to")
    parser.add_argument("--port", type=int, default=int(os.getenv("GRADIO_SERVER_PORT", "7788")), help="Port to listen on")
    parser.add_argument("--theme", type=str, default="Ocean", choices=list(theme_map.keys()), help="Theme for UI")
    args = parser.parse_args()

    config_dict = default_config() 
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    logger.info("Starting Browser Use WebUI...")
    
    demo_instance = create_ui(config_dict, theme_name=args.theme)
    demo_instance.queue().launch(server_name=args.ip, server_port=args.port, share=os.getenv("GRADIO_SHARE", "False").lower() == "true")

if __name__ == '__main__':
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    main()
