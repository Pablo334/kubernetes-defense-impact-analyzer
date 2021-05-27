import json
import argparse
import sys

class Analyzer:
    defense_measures_path = "./defense_measures.json"
    scenario_impact_analysis_path = "./scenario_impact_analysis.json"

    def __init__(self):
        with open(self.defense_measures_path, "r") as f:
            self.defense_measures = json.load(f)
        
        with open(self.scenario_impact_analysis_path, "r") as f:
            self.impact_measures = json.load(f)
    
    def get_scenario_data(self, scenario, tactics, k8s_version):
        self.result = {
            "id": self.impact_measures["Scenarios"][scenario]["id"],
            "name": self.impact_measures["Scenarios"][scenario]["name"],
            "tactics": {}
        }
        
        for tactic in tactics:
            if tactic in self.impact_measures["Scenarios"][scenario]["tactics"]:
                self.result["tactics"][tactic] = self.impact_measures["Scenarios"][scenario]["tactics"][tactic]
        
        self.visualize_data(k8s_version)
        
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
        details["k8s-version-status"] = full_defense_data["k8s-version-status"]
        
        return details


    def visualize_data(self, k8s_version):
        print("==============================================================================================")
        print("Defense measures for scenario {}-{}".format(self.result["id"], self.result["name"]))
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
                    if details["k8s-version-status"][k8s_version] == "DEPRECATED":
                        print("         Measure is deprecated in version {}".format(k8s_version))
                print("     Impact of defensive measures: {}".format(technique["impact"]))
            print("")

        print("==============================================================================================")

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
    parser = CustomParser(description="Script for perfroming Kubernetes defense impact analysis", formatter_class=CustomFormatter)
    parser.add_argument("-s", "--scenario", help="R|Select attack path scenario:\n" 
                                                "1: Exploitation of RCE in application\n"
                                                "2: Supply chain attack\n"
                                                "3: External access by misconfiguration\n", required=True)
    parser.add_argument("-t", "--tactics", type=str, help="R|Comma separated list of Mitre ATT&CK Tactics\n"
                                                "Example: InitialAccess,Execution,Discovery", required=True)
    parser.add_argument("-v", "--version", help="R|Kubernetes Version\n"
                                                "[1.18, 1.19, 1.20, 1.21]\n", default="1.20", required=True)
    args = parser.parse_args()

    tactics = []
    if args.tactics != None:
        tactics = args.tactics.split(",")

    scenario = int(args.scenario) - 1
    version = args.version

    analyzer = Analyzer()
    analyzer.get_scenario_data(scenario, tactics, version)
    

if __name__ == "__main__":
    main()