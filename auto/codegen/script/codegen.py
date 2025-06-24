from os   import path
from time import gmtime
import  re
import  json

from default import CONFIG_FILE_PATH
from default import MIDDLEWARE_MAKEFILE_PATH
from default import METADATA_PATH
from default import TEMPLATE_PATH
from default import TEMPLATE_FILES
from default import OUTPUT_PATH
from default import COMMON_CFG_PARAMS, CONFIG_VALID_PARAMS
from default import CFG_FILE_COMMENT_SYMBOL
from default import VAR_START_REGEX_SYNTAX
from default import VAR_END_REGEX_SYNTAX
from default import VAR_START_OR_END_REGEX_SYNTAX
from default import ARB_CHARS_REGEX_LAZY
from default import TEMPLATE_VAR_HIER_SEPERATOR
from default import TEMPLATE_VAR_MICROOPS_SYNTAX
from default import TEMPLATE_VAR_WILDCARD_SYNTAX
from default import CONFIG_PARAM_NAME_MIDDLEWARE
from default import CONFIG_PARAM_NAME_CRYPTOLIB
from default import CONFIG_PARAM_NAME_UNITESTLIB
from default import CONFIG_PARAM_NAME_SYSINITHOUR
from default import CONFIG_PARAM_NAME_SYSINITMINUTES
from default import CONFIG_PARAM_NAME_SYSINITSECONDS
from default import CONFIG_PARAM_NAME_SYSINITMONTH
from default import CONFIG_PARAM_NAME_SYSINITDATE
from default import CONFIG_PARAM_NAME_SYSINITYEAR
from default import err_types
from micro_ops import MicroOperations

class CodeGenerator:
    """
    -------- entry point of code generation tool in this MQTT client implementation --------
    this module reads all configuration parameters from given configuration file, also read all
    necessary inputs from default.py, which includes
    * user-defined syntax, for parsing template files later.
    * list of file paths of the chosen third-party libraries to include, when building MQTT client library
    * commands to run for building the chosen third-party
    * function name mappings between the chosen middleware and the chosen third-party libraries
    Then render each template file with the loaded config parameters and metadata
    """
    def __init__(
            self, cfg_file_path, template_path, template_files,
            output_path, config_params
        ):
        self.config = config_params
        self.cfg_file_path  = cfg_file_path
        self.template_path  = template_path
        self.template_files = template_files
        self.output_path    = output_path
        self.error          = err_types.ok
        checks_passed = self._input_error_checks()
        if(checks_passed):
            checks_passed = self._parse_cfg_file()
        if(checks_passed):
            checks_passed = self._load_metadata()
        if(checks_passed):
            checks_passed = self._validate_config_params()
        if(checks_passed):
            checks_passed = self._render()
        print("Code generation "+ ("succeed" if checks_passed else "failed") + ", detail status:"+ str(self.error))


    def _input_error_checks(self):
        if(self.config is None):
            self.error = err_types.null_not_allowed
        # check file exitence here
        if (not path.exists(self.cfg_file_path)):
            self.error = {"status": err_types.target_not_exist, "path": self.cfg_file_path}
        if (not path.exists(self.template_path)):
            self.error = {"status": err_types.target_not_exist, "path": self.template_path}
        for item in self.template_files:
            file_full_path = ''.join([self.template_path, "/", item["name"]])
            if (not path.exists(file_full_path)):
                self.error = {"status": err_types.target_not_exist, "path": file_full_path}
        for idx in self.output_path:
            if (not path.exists(self.output_path[idx])):
                self.error = {"status": err_types.target_not_exist, "path": self.output_path[idx]}
        return (True if self.error is err_types.ok else False)


    def _update_cfg_param(self, config, name, value):
        try:
            if(config[name] is not None):
                if(config[name]["set_flag"] is False):
                    config[name]["value"] = value
                    config[name]["set_flag"] = True
                else:
                    self.error = err_types.duplicate_param_name
        except KeyError as e:
            self.error = {"status": err_types.invalid_param_name , "name": name}
        return (True if self.error is err_types.ok else False)


    def _set_sysinit_time(self, config):
        time_param_not_set = True
        for time_param in (CONFIG_PARAM_NAME_SYSINITHOUR, CONFIG_PARAM_NAME_SYSINITMINUTES,
                           CONFIG_PARAM_NAME_SYSINITSECONDS, CONFIG_PARAM_NAME_SYSINITMONTH,
                           CONFIG_PARAM_NAME_SYSINITDATE, CONFIG_PARAM_NAME_SYSINITYEAR):
            time_param_not_set = time_param_not_set and config[time_param]["set_flag"]
        if(not time_param_not_set):
            curr_time = gmtime()
            config[CONFIG_PARAM_NAME_SYSINITHOUR   ]["value"] = curr_time.tm_hour
            config[CONFIG_PARAM_NAME_SYSINITMINUTES]["value"] = curr_time.tm_min
            config[CONFIG_PARAM_NAME_SYSINITSECONDS]["value"] = curr_time.tm_sec 
            config[CONFIG_PARAM_NAME_SYSINITMONTH  ]["value"] = curr_time.tm_mon 
            config[CONFIG_PARAM_NAME_SYSINITDATE   ]["value"] = curr_time.tm_mday
            config[CONFIG_PARAM_NAME_SYSINITYEAR   ]["value"] = curr_time.tm_year
            curr_time = None


    def _parse_cfg_file(self):
        lines = None
        for name in self.config:
            self.config[name]["set_flag"] = False
        with open(self.cfg_file_path, "r") as cfg_file:
            lines = cfg_file.read().splitlines()
        for line in lines:
            if(len(line) == 0):
                continue # skip empty line
            comment = re.findall(''.join(["^[ ]*?", CFG_FILE_COMMENT_SYMBOL]) , line, re.S)
            if(len(comment) != 0):
                continue # skip if it's comment
            line = line.split(CFG_FILE_COMMENT_SYMBOL)
            line = re.split("[ ]+", line[0].strip())
            # every configuration parameter should come with (name, value) pair
            if(len(line) < 2):
                self.error = {"status": err_types.incomplete_param_pair, "rootcause": line}
                break
            elif(len(line[1]) == 0):
                self.error = {"status": err_types.incomplete_param_pair, "rootcause": line}
                break
            elif(len(line) > 2 and len(line[2]) != 0):
                self.error = {"status": err_types.incomplete_param_pair, "rootcause": line}
                break
            if(not self._update_cfg_param(self.config, line[0], line[1])):
                break
            ####print("keywords of a line: " + str(line))
        # if date/time is NOT specified in user configuration file, then this script automatically
        # get current date/time from underlying OS
        self._set_sysinit_time(self.config)
        return (True if self.error is err_types.ok else False)
#### end of CodeGenerator._parse_cfg_file

    def _validate_config_params(self) -> bool:
        """
        Validates that configuration parameters set in mqttclient.conf are
        applicable to the chosen middleware.
        """
        middleware_name = self.config[CONFIG_PARAM_NAME_MIDDLEWARE]["value"]
        middleware_metadata = self.config[CONFIG_PARAM_NAME_MIDDLEWARE]["metadata"]
        # Get the set of parameters explicitly supported by the chosen middleware
        supported_middleware_params = set(middleware_metadata.get("supported_config_params", []))
        for param_name, param_data in self.config.items():
            # Only check parameters that were explicitly set in the config file
            # (i.e., not default values from CONFIG_VALID_PARAMS)
            if param_data["set_flag"]:
                # Check if the parameter is not common AND not supported by the current middleware  
                if param_name not in COMMON_CFG_PARAMS and param_name not in supported_middleware_params:
                    self.error = {
                        "status": err_types.param_not_applicable,
                        "name": param_name,
                        "middleware": middleware_name
                    }
                    return False
        # Also perform the middleware makefile existence check here, as it depends
        # on the middleware value
        filepath = [MIDDLEWARE_MAKEFILE_PATH, "/", middleware_name, ".makefile"]
        if not path.exists(''.join(filepath)):
            self.error = {"status": err_types.target_not_exist, "path": ''.join(filepath)}
            return False
        return (True if self.error is err_types.ok else False)


    def _load_metadata(self): # load JSON-based metadata
        filepath = [METADATA_PATH, "/", None, ".json"]
        try:
            for name in (CONFIG_PARAM_NAME_MIDDLEWARE, CONFIG_PARAM_NAME_UNITESTLIB,
                         CONFIG_PARAM_NAME_CRYPTOLIB):
                filepath[2] = self.config[name]["value"]
                with open(''.join(filepath), 'r') as f:
                    self.config[name]["metadata"] = json.load(f)
        except FileNotFoundError as e:
            self.error = {"status": err_types.target_not_exist, "path": e.filename}
        except json.decoder.JSONDecodeError as e:
            self.error = {"status": err_types.metadata_decode_error, "detail": e}
        return (True if self.error is err_types.ok else False)


    def _load_template(self, filepath, vars_render):
        var_re = [ARB_CHARS_REGEX_LAZY, VAR_START_REGEX_SYNTAX, "(", None, None, None, ")", VAR_END_REGEX_SYNTAX]
        with open(filepath ,'r') as f:
            template_content = f.read() # TODO: find better way to handle large-sized file
        var_re[3] = "[^("   # variable name can contain any character except VAR_START_REGEX_SYNTAX
        var_re[4] = VAR_START_REGEX_SYNTAX
        var_re[5] = ")]*?"
        var_list = re.findall(''.join(var_re), template_content, re.S) # only collect all variables
        # seperate variables from other plaintext content, by specified variable syntax
        var_re[4] = VAR_START_OR_END_REGEX_SYNTAX
        template_content = re.split(var_re[4], template_content)
        # print("[parsed] output: "+ str(template_content))
        for idx in range(len(var_list)): # initialize data structure for each variable
            var_list[idx] = var_list[idx].strip()
            vars_render[var_list[idx]] = {"data_hier":None, "micro_ops":None, "output":None, "template":None, "pos":0};
        # find the position of each variable in a given template, useful at later rendering process
        for idx in range(len(template_content)):
            potenial_var = template_content[idx].strip()
            try:
                if(vars_render[potenial_var] is not None):
                    vars_render[potenial_var]["pos"] = idx
            except KeyError as e:
                pass
        # extract format of variable hierarchy, which should be like : var0.variable.var1.var2@micro_ops1@micro_ops2
        for key in vars_render:
            vars_render[key]["template"]   = template_content
            vars_render[key]["data_hier"]  = re.split(TEMPLATE_VAR_HIER_SEPERATOR, key)
            last_data_hier = vars_render[key]["data_hier"][-1]
            vars_render[key]["micro_ops"] = re.split(TEMPLATE_VAR_MICROOPS_SYNTAX, last_data_hier)
            vars_render[key]["micro_ops"].pop(0)
            if(len(vars_render[key]["micro_ops"]) > 0):
                vars_render[key]["data_hier"][-1] = last_data_hier[:last_data_hier.find(TEMPLATE_VAR_MICROOPS_SYNTAX)]
#### end of _load_template


    def _recursive_lookup_config(self, config, var_render, depth):
        data_hier   = var_render["data_hier"]
        if(config is None or isinstance(config, dict) is False):
            return
        elif(data_hier[depth] is data_hier[-1]):
            if(var_render["output"] is None):
                var_render["output"] = config[data_hier[depth]]
            elif(config[data_hier[depth]] is not None):
                var_render["output"] += config[data_hier[depth]]
        else:
            if(data_hier[depth] is TEMPLATE_VAR_WILDCARD_SYNTAX):
                for idx in config:
                    try:
                        self._recursive_lookup_config(config[idx], var_render, depth + 1)
                    except KeyError as e:
                        pass
            else:
                self._recursive_lookup_config(config[data_hier[depth]], var_render, depth + 1)

    def _render_post_process(self, config, var_render):
        if(var_render["output"] is None):
            var_render["output"] = ''
        elif(var_render["micro_ops"]):
            try:
                MicroOperations.middleware_sys_fn_map = config[CONFIG_PARAM_NAME_MIDDLEWARE]["metadata"]["sys_fn_map"]
                for op in var_render["micro_ops"]:
                    var_render["output"] = MicroOperations.fn_map[op]( var_render["output"] )
            except (KeyError, ValueError, TypeError) as e:
                self.error = {"status": err_types.invalid_micro_op, "path": e}
            except FileNotFoundError as e:
                self.error = {"status": err_types.target_not_exist, "path": e.filename}
            #### print("[loop] .... data_hier: "+ str(var_render["data_hier"]) +" , micro_ops: "+ str(var_render["micro_ops"]))
            MicroOperations.middleware_sys_fn_map = None
        return (True if self.error is err_types.ok else False)


    def _render(self):
        vars_render = {}
        # load extract template file, substitute
        for item in self.template_files:
            checks_passed = True
            file_full_path = ''.join([self.template_path, "/", item["name"]])
            self._load_template(file_full_path, vars_render)
            # estimate hierarchical path of each variable, extract optional micro commands
            for key in vars_render:
                ## look up appropriate value by variable hierarchical path
                self._recursive_lookup_config(self.config, vars_render[key], 0)
                checks_passed = self._render_post_process(self.config, vars_render[key])
                if(checks_passed):
                    checks_passed = self._render_template(vars_render[key])
                if(not checks_passed):
                    break
            print("Rendering template file "+ item["name"] +" .... "+ ("ok" if checks_passed else "failed"))
            #print("[parsed] output: "+ str(vars_render[key]["template"]))
            if(checks_passed):
                file_full_path = ''.join([self.output_path[item["type"]], "/",  item["name"]])
                with open(file_full_path, "w") as f: # write modified template out to file
                    f.write(''.join(vars_render[key]["template"]))

            for key in vars_render:
                vars_render[key]["micro_ops"].clear()
                vars_render[key]["data_hier"].clear()
                ### vars_render[key]["output"].clear()
                vars_render[key].clear()
            vars_render.clear()
            if(not checks_passed):
                break
            # print("[final] vars_render: "+ str(vars_render))
        vars_render = None
        return (True if self.error is err_types.ok else False)

                #### print("[loop] .... data_hier:\t"+ str(vars_render[key]["data_hier"]) )
                #### if(isinstance(vars_render[key]["output"], str) is True and len(vars_render[key]["output"]) > 100):
                ####     print("[loop] .... output:\t"+ str(vars_render[key]["output"][:100]))
                #### else:
                ####     print("[loop] .... output:\t"+ str(vars_render[key]["output"]))

    def _render_template(self, var_render):
        pos = var_render["pos"]
        if(isinstance(var_render["output"] ,list)):
            parse_str = ''.join(var_render["output"])
            var_render["output"].clear()
        else:
            parse_str = str(var_render["output"])
        var_render["template"][pos] = parse_str
        return (True if self.error is err_types.ok else False)


if __name__ == "__main__":
    CodeGenerator(
        cfg_file_path=CONFIG_FILE_PATH,
        template_path=TEMPLATE_PATH,
        template_files=TEMPLATE_FILES,
        output_path=OUTPUT_PATH,
        config_params=CONFIG_VALID_PARAMS
    )


