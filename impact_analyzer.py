import json
from argparse import ArgumentParser,SUPPRESS,HelpFormatter
import sys
import os
from datetime import datetime
from bs4 import BeautifulSoup
from termcolor import colored

class Protector:
    defense_measures_path = "./defense_measures.json"
    scenario_impact_analysis_path = "./scenario_impact_analysis.json"
    output_directory = "./output"
    asset_directory = "./assets"
    html_template = "analyzer_output_template.html"

    def __init__(self, mode, tactics, output):
        self.load_data_from_file()
        self.mode = mode
        self.tactics = tactics
        self.output = output
    
    # Load data from json files
    @classmethod
    def load_data_from_file(cls):
        with open(cls.defense_measures_path, "r") as f:
            cls.defense_measures = json.load(f)
        
        with open(cls.scenario_impact_analysis_path, "r") as f:
            cls.impact_measures = json.load(f)

    # Get scenario data with selected tactics from storage
    def get_scenario_data(self, scenario, k8s_version):
        self.result = {
            "id": self.impact_measures["Scenarios"][scenario]["id"],
            "name": self.impact_measures["Scenarios"][scenario]["name"],
            "tactics": {}
        }
        
        if "All" in self.tactics:
            self.result["tactics"] = self.impact_measures["Scenarios"][scenario]["tactics"]
        else:
            for tactic in self.tactics:
                if tactic in self.impact_measures["Scenarios"][scenario]["tactics"]:
                    self.result["tactics"][tactic] = self.impact_measures["Scenarios"][scenario]["tactics"][tactic]
        
        # Output
        if self.output == "json":
            self.analyze_output_json(k8s_version)
        elif self.output == "stdout":
            self.analyze_output_stdout(k8s_version)
        elif self.output == "txt":
            self.analyze_output_txt(k8s_version)
        else:
            self.output_html(k8s_version, "analyzer")
        
    # Get details from defense ids
    def get_defense_details(self, defense_id, k8s_version):
        details = {}
        defense_id_split_list = defense_id.split(".")
        root_category_defense_id = int(defense_id_split_list[0])-1
        defense_category = self.defense_measures["DefenseMeasures"][root_category_defense_id]
        details["category"] = defense_category["name"]

        level = len(defense_id_split_list)
        full_defense_data = {}
        if level == 3:
            full_defense_data = self.defense_measures["DefenseMeasures"][root_category_defense_id]["sub-measures"][int(defense_id_split_list[1])-1]["sub-measures"][int(defense_id_split_list[2])-1]
        else:
            full_defense_data = self.defense_measures["DefenseMeasures"][root_category_defense_id]["sub-measures"][int(defense_id_split_list[1])-1]
        
        details["id"] = full_defense_data["id"]
        details["name"] = full_defense_data["name"]
        details["type"] = full_defense_data["type"]

        if "template" in full_defense_data:
            details["template"] = full_defense_data["template"]

        if "k8s-version-status" in full_defense_data:
            details["k8s-version-status"] = full_defense_data["k8s-version-status"]
        
        return details

    # Write output to stdout
    def analyze_output_stdout(self, k8s_version):
        print("==============================================================================================")
        print("Defense measures for {}".format(self.result["name"]))
        print("")

        for key in self.result["tactics"]:
            print(colored("#{}".format(key), "cyan"))
            for technique in self.result["tactics"][key]["techniques"]:
                print(" {}-{}".format(technique["id"], technique["name"]) )
                print("     Enabled defense measures")
                for defense in technique["defenses"]:
                    details = self.get_defense_details(defense["id"], k8s_version)
                    print("         Category: {}".format(details["category"]))
                    print("         Measure: {} {}".format(defense["id"],details["name"]))
                    print("         Type: {}".format(details["type"]))
                    if details["k8s-version-status"][k8s_version]["status"] == "DEPRECATED":
                        print("         Measure is deprecated in version {}".format(k8s_version))  
                    print("         For more information visit {}".format(details["k8s-version-status"][k8s_version]["info"]))
                    if "template" in details:
                        print("         Template: {}".format(details["template"]))

                impact = ""
                if technique["impact"] == "FULL IMPACT":
                    impact = colored(technique["impact"], "red")
                elif technique["impact"] == "PARTIAL IMPACT":
                    impact = colored(technique["impact"], "magenta")
                elif technique["impact"] == "LOW IMPACT":
                    impact = colored(technique["impact"], "yellow")
                else:
                    impact = colored(technique["impact"], "blue")

                print("     Impact of defensive measures: {}".format(impact))
            print("")

        print("==============================================================================================")
    
    # Generate json output
    def analyze_output_json(self, k8s_version):
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        dump = self.result

        for tactic in dump["tactics"]:
            for technique in dump["tactics"][tactic]["techniques"]:
                for defense in technique["defenses"]:
                    details = self.get_defense_details(defense["id"], k8s_version)
                    defense["name"] = details["name"]
                    defense["category"] = details["category"]
                    defense["type"] = details["type"]
                    defense["k8s-version-status"] = details["k8s-version-status"]
                    defense["template"] = details["template"]

        filename = "{}/Analyzer-Output-{}.json".format(self.output_directory,datetime.now())
        with open(filename, "w") as f:
            json.dump(dump,f,indent=4)
        print(json.dumps(self.result, indent=4))

    # Generate txt output
    def analyze_output_txt(self, k8s_version):
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        filename = "{}/Analyzer-Output-{}.txt".format(self.output_directory, datetime.now())
        with open(filename, "w") as f:
            f.write("Defense measures for {}\n".format(self.result["name"]))
            f.write("\n")

            for key in self.result["tactics"]:
                f.write("#{}\n".format(key))
                f.write(" Attack Techniques\n")
                for technique in self.result["tactics"][key]["techniques"]:
                    f.write(" {}-{}\n".format(technique["id"], technique["name"]) )
                    f.write("     Enabled defense measures\n")
                    for defense in technique["defenses"]:

                        details = self.get_defense_details(defense["id"], k8s_version)
                        f.write("         Category: {}\n".format(details["category"]))
                        f.write("         Measure: {} {}\n".format(defense["id"],details["name"]))
                        f.write("         Type: {}\n".format(details["type"]))

                        if details["k8s-version-status"][k8s_version]["status"] == "DEPRECATED":
                            f.write("         Measure is deprecated in version {}\n".format(k8s_version))
                            
                        f.write("         For more information visit {}\n".format(details["k8s-version-status"][k8s_version]["info"]))
                        if "template" in details:
                            f.write("         Template: {}\n".format(details["template"]))
                    f.write("     Impact of defensive measures: {}\n".format(technique["impact"]))
                f.write("\n")
    
    # Generate html output
    def output_html(self, k8s_version, mode):
        if not os.path.exists(self.asset_directory):
            print("[!][!] Directory {} does not exist".format(self.asset_directory))
            sys.exit(2)
        
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        with open("{}/{}".format(self.asset_directory, self.html_template), "r") as f:
            self.soup = BeautifulSoup(f, "html.parser")

        generation_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        if mode == "template":
            title_string = "Getting started templates for Kubernetes defensive measures"
        else:
            title_string = "Kubernetes defense report generated on {} - Version {}".format(generation_time, k8s_version)

        report_title_h1 = self.soup.new_tag("h1")
        report_title_h1.string = title_string
        
        self.soup.head.title.string = "Output {}".format(generation_time)
        
        if mode == "template":
            self.soup.body.append(self.soup_build_get_started_template(report_title_h1))
            file_intro_name = "Template-Output"
        else:
            self.soup.body.append(self.soup_build_impact(report_title_h1, k8s_version))
            file_intro_name = "Analyzer-Output"


        filename = "{}/{}-{}.html".format(self.output_directory, file_intro_name, datetime.now())
        with open(filename, "w") as f:
            f.write(self.soup.prettify())

    # Build html file for analyzer mode (defensive impact)
    def soup_build_impact(self, report_title_h1, k8s_version):
        container_div = self.soup.new_tag("div", id="container")
        
        container_div.append(report_title_h1)

        for key in self.result["tactics"]:

            # Create div for tactic
            tactic_div = self.soup.new_tag("div", id="{}".format("sub-container"))
            tactic_h2 = self.soup.new_tag("h2")
            tactic_h2.string = "{}".format(key)
            tactic_div.append(tactic_h2)

            for technique in self.result["tactics"][key]["techniques"]:
                # Create div for technique
                technique_div = self.soup.new_tag("div", id="{}".format(technique["id"]), **{'class': 'techniqueDiv'})
                technique_name_h3 = self.soup.new_tag("h3")
                technique_name_h3.string = "{}-{}".format(technique["id"], technique["name"])
                technique_div.append(technique_name_h3) 

                impact_p = self.soup.new_tag("p")
                if technique["impact"] == "LOW IMPACT":
                    impact_span = self.soup.new_tag("span", **{'class': 'low'} )
                elif technique["impact"] == "PARTIAL IMPACT":
                    impact_span = self.soup.new_tag("span", **{'class': 'partial'} )
                else:
                    impact_span = self.soup.new_tag("span", **{'class': 'full'} )

                impact_span.string = "Score: {}".format(technique["impact"])
                impact_p.append(impact_span)
                
                technique_div.append(impact_p)

                # Create table with header rows
                table = self.soup.new_tag("table", id="table-{}".format(technique["id"]))
                header_row = self.soup.new_tag("tr")

                header1 = self.soup.new_tag("th")
                header1.string = "Id"
                header_row.append(header1)

                header2 = self.soup.new_tag("th")
                header2.string = "Measure"
                header_row.append(header2)

                header3 = self.soup.new_tag("th")
                header3.string = "Category"
                header_row.append(header3)

                header4 = self.soup.new_tag("th")
                header4.string = "Type"
                header_row.append(header4)

                header5 = self.soup.new_tag("th")
                header5.string = "Version Compatibility"
                header_row.append(header5)

                header6 = self.soup.new_tag("th")
                header6.string = "Info"
                header_row.append(header6)

                header7 = self.soup.new_tag("th")
                header7.string = "Template"
                header_row.append(header7)

                #header8 = soup.new_tag("th")
                #header8.string = "Help"
                #header_row.append(header8)

                table.append(header_row)

                # Set defense measures in table
                for defense in technique["defenses"]:
                    # Get details from defense id
                    details = self.get_defense_details(defense["id"], k8s_version)
                    row = self.soup.new_tag("tr")

                    # Id field
                    data_id = self.soup.new_tag("td")
                    data_id.string = "{}".format(defense["id"])
                    row.append(data_id)

                    # Name field
                    measure = self.soup.new_tag("td")
                    measure.string = "{}".format(details["name"])
                    row.append(measure)

                    # Category field
                    category = self.soup.new_tag("td")
                    category.string = "{}".format(details["category"])
                    row.append(category)

                    # Type field
                    defense_type = self.soup.new_tag("td")
                    defense_type.string = "{}".format(details["type"])
                    row.append(defense_type)

                    # Compatibility field: shows status in selected k8s version
                    compatibility = self.soup.new_tag("td")

                    # Info and Help fields: additional resources to help with setup
                    info_td = self.soup.new_tag("td")
                    #help_td = soup.new_tag("td")
                    template_td = self.soup.new_tag("td")
                    
                    info_a = self.soup.new_tag("a", href=details["k8s-version-status"][k8s_version]["info"])
                    info_a.string = details["k8s-version-status"][k8s_version]["info"]
                    #help_a = soup.new_tag("a", href=defense["help"])
                    
                    if details["k8s-version-status"][k8s_version]["status"] == "DEPRECATED":
                        compatibility.string = "Deprecated in version {}".format(k8s_version)
                        #help_a.string = ""
                    else:
                        compatibility.string = "OK"
                        #help_a.string = defense["help"]

                    template_a = ""
                    if "template" in details:
                        template_a = self.soup.new_tag("a", href=details["template"])
                        template_a.string = details["template"]

                    info_td.append(info_a)
                    #help_td.append(help_a)
                    template_td.append(template_a)
                    
                    row.append(compatibility)
                    row.append(info_td)
                    #row.append(help_td)
                    row.append(template_td)
                    
                    table.append(row)

                technique_div.append(table)
                tactic_div.append(technique_div)
            
            container_div.append(tactic_div)

        return container_div

    # Build html file for getting started mode
    def soup_build_get_started_template(self, report_title_h1):
        container_div = self.soup.new_tag("div", id="container")
        
        container_div.append(report_title_h1)

        for defense_id in self.templates.keys():
            defense_div = self.soup.new_tag("div", id="{}".format(defense_id), **{'class': 'techniqueDiv'})
            technique_name_h3 = self.soup.new_tag("h3")
            technique_name_h3.string = "{}-{}".format(defense_id, self.templates[defense_id]["defense_name"])
            defense_div.append(technique_name_h3) 

            defense_p = self.soup.new_tag("p")
            defense_a = self.soup.new_tag("a", href=self.templates[defense_id]["template"])
            defense_a.string = self.templates[defense_id]["template"]
            defense_p.string = "Gist Link: "
            defense_p.append(defense_a)

            defense_div.append(defense_p)

            container_div.append(defense_div)
        return container_div

    # Get template data for selected tactics from storage
    def get_only_templates(self):
        Protector.load_data_from_file()
        
        self.templates = {}

        if "All" in self.tactics:
            for defense_measure in self.defense_measures["DefenseMeasures"]:
                for sub_measure in defense_measure["sub-measures"]:
                    if "template" in sub_measure:
                        self.templates[sub_measure["id"]] = {}
                        self.templates[sub_measure["id"]]["defense_name"] = sub_measure["name"]
                        self.templates[sub_measure["id"]]["template"] = sub_measure["template"]
        else:
            defense_ids = []
            for tactic in self.tactics:
                for scenario in self.impact_measures["Scenarios"]:
                    if tactic in scenario["tactics"]:
                        for technique in scenario["tactics"][tactic]["techniques"]:
                            for defense in technique["defenses"]:
                                defense_ids.append(defense["id"])
            
            formatted_defense_ids = []
            for defense_id in defense_ids:
                if len(defense_id.split(".")) == 3:
                    formatted_defense_ids.append(".".join(defense_id.split(".")[0:2]))
                else:
                    formatted_defense_ids.append(defense_id)
            
            for defense_measure in self.defense_measures["DefenseMeasures"]:
                for sub_measure in defense_measure["sub-measures"]:
                    if "template" in sub_measure:
                        if sub_measure["id"] in formatted_defense_ids:
                            self.templates[sub_measure["id"]] = {}
                            self.templates[sub_measure["id"]]["defense_name"] = sub_measure["name"]
                            self.templates[sub_measure["id"]]["template"] = sub_measure["template"]
        
        if self.output == "json":

            filename = "{}/Template-Output-{}.json".format(self.output_directory, datetime.now())
            with open(filename, "w") as f:
                json.dump(self.templates, f, indent=4)
            print(json.dumps(self.templates, indent=4))

        else:
            self.output_html(k8s_version="", mode="template")
        
# Override of ArgumentParser for custom error messages
class CustomParser(ArgumentParser):
    def error(self, message):
        usage = self.usage
        self.usage = None
        self.print_usage(sys.stderr)
        self.exit(2, ('%s: error: %s\n') % (self.prog, message))
        self.usage = usage

# Override of HelpFormatter for custom help message formatting
class CustomFormatter(HelpFormatter):
    def _split_lines(self, text, width):
        if text.startswith('R|'):
            return text[2:].splitlines()  
        return HelpFormatter._split_lines(self, text, width)

def main():
    tactics_list_of_choices = ["All", "Reconnaissance", "InitialAccess", "Execution", "Discovery", "LateralMovement", "PrivilegeEscalation", "Collection", "DefenseEvasion"]
    output_list_of_choices = ["stdout", "json", "txt", "html"]

    parser = CustomParser(description="Script for perfroming Kubernetes defense impact analysis", formatter_class=CustomFormatter, usage=SUPPRESS)
    
    subparser = parser.add_subparsers(help="sub-command help", dest="mode")

    parser_analyzer = subparser.add_parser("analyzer", help="analyzer help")
    parser_analyzer.add_argument("-s", "--scenario", help="R|Select attack path scenario:\n" 
                                                "1: Exploitation of RCE in application\n"
                                                "2: Supply chain attack\n"
                                                "3: External access by misconfiguration\n", required=True, choices=["1","2","3"])
    parser_analyzer.add_argument("-t", "--tactics", type=str, help="List of Mitre ATT&CK Tactics\n", required=True, 
                                            choices=tactics_list_of_choices, nargs="+")
    parser_analyzer.add_argument("-v", "--version", help="R|Kubernetes Version\n"
                                                "[1.18, 1.19, 1.20, 1.21]\n", default="1.20", required=True)
    parser_analyzer.add_argument("-o", "--output", help="Output method", default="stdout", choices=output_list_of_choices)
    
    parser_template = subparser.add_parser("template", help="template help")
    parser_template.add_argument("-t", "--tactics", type=str, help="List of Mitre ATT&CK Tactics\n", required=True, 
                                            choices=tactics_list_of_choices, nargs="+")
    parser_template.add_argument("-o", "--output", help="Output method", default="stdout", choices=output_list_of_choices)

    args = parser.parse_args()

    # Arguments
    if args.mode == "analyzer":
        scenario = int(args.scenario) - 1
        analyzer = Protector(args.mode, args.tactics, args.output)
        analyzer.get_scenario_data(scenario, args.version)
    elif args.mode == "template":
        protector = Protector(args.mode, args.tactics, args.output)
        templates = protector.get_only_templates()
    else:
        parser.print_help()
        sys.exit(2) 
    
    

if __name__ == "__main__":
    main()