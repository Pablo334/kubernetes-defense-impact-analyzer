import json
import argparse
import sys
import os
from datetime import datetime
from bs4 import BeautifulSoup

class Analyzer:
    defense_measures_path = "./defense_measures.json"
    scenario_impact_analysis_path = "./scenario_impact_analysis.json"
    output_directory = "./output"
    asset_directory = "./assets"
    html_template = "output_template.html"

    def __init__(self, scenario, tactics, k8s_version, output):
        with open(self.defense_measures_path, "r") as f:
            self.defense_measures = json.load(f)
        
        with open(self.scenario_impact_analysis_path, "r") as f:
            self.impact_measures = json.load(f)
        
        self.scenario = scenario
        self.tactics = tactics
        self.k8s_version = k8s_version
        self.output = output
    
    # Get scenario data with selected tactics from storage
    def get_scenario_data(self):
        self.result = {
            "id": self.impact_measures["Scenarios"][self.scenario]["id"],
            "name": self.impact_measures["Scenarios"][self.scenario]["name"],
            "tactics": {}
        }
        
        for tactic in self.tactics:
            if tactic in self.impact_measures["Scenarios"][self.scenario]["tactics"]:
                self.result["tactics"][tactic] = self.impact_measures["Scenarios"][self.scenario]["tactics"][tactic]
        
        # Output
        if self.output == "json":
            self.output_json()
        elif self.output == "stdout":
            self.output_stdout(k8s_version)
        elif self.output == "txt":
            self.output_txt(k8s_version)
        else:
            self.output_html()
        
    # Get details from defense ids
    def get_defense_details(self, defense_id):
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
        details["k8s-version-status"] = full_defense_data["k8s-version-status"]
        
        return details

    # Write output to stdout
    def output_stdout(self):
        print("==============================================================================================")
        print("Defense measures for {}".format(self.result["name"]))
        print("")

        for key in self.result["tactics"]:
            print("#{}".format(key))
            print(" Attack Techniques")
            for technique in self.result["tactics"][key]["techniques"]:
                print(" {}-{}".format(technique["id"], technique["name"]) )
                print("     Enabled defense measures")
                for defense in technique["defenses"]:
                    details = self.get_defense_details(defense["id"])
                    print("         Category: {}".format(details["category"]))
                    print("         Measure: {} {}".format(defense["id"],details["name"]))
                    print("         Type: {}".format(details["type"]))
                    if details["k8s-version-status"][self.k8s_version] == "DEPRECATED":
                        print("         Measure is deprecated in version {}".format(self.k8s_version))
                print("     Impact of defensive measures: {}".format(technique["impact"]))
            print("")

        print("==============================================================================================")
    
    # Write output to json
    def output_json(self):
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        with open("{}/{}.json".format(self.output_directory,datetime.now()), "w") as f:
            json.dump(self.result,f)
        print(self.result)

    # Write output to txt
    def output_txt(self):
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        with open("{}/{}.txt".format(self.output_directory, datetime.now()), "w") as f:
            f.write("Defense measures for {}\n".format(self.result["name"]))
            f.write("\n")

            for key in self.result["tactics"]:
                f.write("#{}\n".format(key))
                f.write(" Attack Techniques\n")
                for technique in self.result["tactics"][key]["techniques"]:
                    f.write(" {}-{}\n".format(technique["id"], technique["name"]) )
                    f.write("     Enabled defense measures\n")
                    for defense in technique["defenses"]:
                        details = self.get_defense_details(defense["id"])
                        f.write("         Category: {}\n".format(details["category"]))
                        f.write("         Measure: {} {}\n".format(defense["id"],details["name"]))
                        f.write("         Type: {}\n".format(details["type"]))
                        if details["k8s-version-status"][self.k8s_version] == "DEPRECATED":
                            f.write("         Measure is deprecated in version {}\n".format(self.k8s_version))
                    f.write("     Impact of defensive measures: {}\n".format(technique["impact"]))
                f.write("\n")
    
    # Generate html output
    def output_html(self):
        if not os.path.exists(self.asset_directory):
            print("[!][!] Directory {} does not exist".format(self.asset_directory))
            sys.exit(2)
        
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        with open("{}/{}".format(self.asset_directory, self.html_template), "r") as f:
            soup = BeautifulSoup(f, "html.parser")
        
        generation_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        soup.head.title.string = "Output {}".format(generation_time)
        container_div = soup.new_tag("div", id="container")
        report_title_h1 = soup.new_tag("h1")
        report_title_h1.string = "Kubernetes defense report generated on {}".format(generation_time)
        container_div.append(report_title_h1)
        for key in self.result["tactics"]:

            # Create div for tactic
            tactic_div = soup.new_tag("div", id="{}".format("sub-container"))
            tactic_h2 = soup.new_tag("h2")
            tactic_h2.string = "{}".format(key)
            tactic_div.append(tactic_h2)

            for technique in self.result["tactics"][key]["techniques"]:
                # Create div for technique
                technique_div = soup.new_tag("div", id="{}".format(technique["id"]), **{'class': 'techniqueDiv'})
                technique_name_h3 = soup.new_tag("h3")
                technique_name_h3.string = "{}-{}".format(technique["id"], technique["name"])
                technique_div.append(technique_name_h3) 

                impact_p = soup.new_tag("p")
                if technique["impact"] == "LOW IMPACT":
                    impact_span = soup.new_tag("span", **{'class': 'low'} )
                elif technique["impact"] == "PARTIAL IMPACT":
                    impact_span = soup.new_tag("span", **{'class': 'partial'} )
                else:
                    impact_span = soup.new_tag("span", **{'class': 'full'} )

                impact_span.string = "Score: {}".format(technique["impact"])
                impact_p.append(impact_span)
                
                technique_div.append(impact_p)

                # Create table with header rows
                table = soup.new_tag("table", id="table-{}".format(technique["id"]))
                header_row = soup.new_tag("tr")

                header1 = soup.new_tag("th")
                header1.string="Id"
                header_row.append(header1)

                header2 = soup.new_tag("th")
                header2.string="Measure"
                header_row.append(header2)

                header3 = soup.new_tag("th")
                header3.string="Category"
                header_row.append(header3)

                header4 = soup.new_tag("th")
                header4.string="Type"
                header_row.append(header4)

                header5 = soup.new_tag("th")
                header5.string="Version Compatibility"
                header_row.append(header5)

                header6 = soup.new_tag("th")
                header6.string="Info"
                header_row.append(header6)

                table.append(header_row)

                # Set defense measures in table
                for defense in technique["defenses"]:
                    # Get details from defense id
                    details = self.get_defense_details(defense["id"])
                    row = soup.new_tag("tr")

                    #Id field
                    data_id = soup.new_tag("td")
                    data_id.string = "{}".format(defense["id"])
                    row.append(data_id)

                    #Name field
                    measure = soup.new_tag("td")
                    measure.string = "{}".format(details["name"])
                    row.append(measure)

                    #Category field
                    category = soup.new_tag("td")
                    category.string = "{}".format(details["category"])
                    row.append(category)

                    #Type field
                    defense_type = soup.new_tag("td")
                    defense_type.string = "{}".format(details["type"])
                    row.append(defense_type)

                    #Compatibility field: shows status in selected k8s version
                    compatibility = soup.new_tag("td")
                    info = soup.new_tag("td")
                    if details["k8s-version-status"][self.k8s_version] == "DEPRECATED":
                        compatibility.string = "Deprecated in version {}".format(self.k8s_version)
                        info.string = "Lookup OPA Gatekeeper"
                    else:
                        compatibility.string = "OK"
                    
                    row.append(compatibility)
                    row.append(info)
                    
                    table.append(row)

                technique_div.append(table)
                tactic_div.append(technique_div)
            
            container_div.append(tactic_div)
        soup.body.append(container_div)

        with open("{}/{}.html".format(self.output_directory, datetime.now()), "w") as f:
            f.write(soup.prettify())


# Override of ArgumentParser for custom error messages
class CustomParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.exit(2)

# Override of HelpFormatter for custom help message formatting
class CustomFormatter(argparse.HelpFormatter):
    def _split_lines(self, text, width):
        if text.startswith('R|'):
            return text[2:].splitlines()  
        return argparse.HelpFormatter._split_lines(self, text, width)

def main():
    tactics_list_of_choices = ["Reconnaissance", "InitialAccess", "Execution", "Discovery", "LateralMovement", "PrivilegeEscalation", "Collection", "DefenseEvasion"]
    output_list_of_choices = ["stdout", "json", "txt", "html"]

    parser = CustomParser(description="Script for perfroming Kubernetes defense impact analysis", formatter_class=CustomFormatter)
    parser.add_argument("-s", "--scenario", help="R|Select attack path scenario:\n" 
                                                "1: Exploitation of RCE in application\n"
                                                "2: Supply chain attack\n"
                                                "3: External access by misconfiguration\n", required=True, choices=["1","2","3"])
    parser.add_argument("-t", "--tactics", type=str, help="List of Mitre ATT&CK Tactics\n", required=True, 
                                            choices=tactics_list_of_choices, nargs="+")
    parser.add_argument("-v", "--version", help="R|Kubernetes Version\n"
                                                "[1.18, 1.19, 1.20, 1.21]\n", default="1.20", required=True)
    parser.add_argument("-o", "--output", help="Output method", default="stdout", choices=output_list_of_choices)
    args = parser.parse_args()

    # Arguments
    tactics = args.tactics
    scenario = int(args.scenario) - 1
    version = args.version
    output = args.output

    analyzer = Analyzer(scenario, tactics, version, output)
    analyzer.get_scenario_data()
    

if __name__ == "__main__":
    main()