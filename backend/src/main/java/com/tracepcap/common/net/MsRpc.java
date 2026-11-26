package com.tracepcap.common.net;

import java.util.Locale;
import java.util.Map;

/**
 * Microsoft RPC interfaces by UUID, and the names of the operations that matter for an
 * investigation (#1266). Suricata logs a DCE-RPC call as an interface UUID and an operation number;
 * this turns {@code 367abb81-… opnum 12} into "svcctl CreateServiceW".
 *
 * <p>UUIDs and operation numbers are from Microsoft's protocol specifications ([MS-SCMR],
 * [MS-TSCH], [MS-DRSR], [MS-SAMR], [MS-LSAD], [MS-RRP], [MS-SRVS], [MS-NRPC], [MS-WMI], [MS-RPRN],
 * [MS-EFSR], [MS-EVEN6]). Only the operations someone would act on are named; any other is shown as
 * its number.
 */
public final class MsRpc {

  private MsRpc() {}

  public static final String SVCCTL = "367abb81-9844-35f1-ad32-98f038001003";
  public static final String ATSVC = "1ff70682-0a51-30e8-076d-740be8cee98b";
  public static final String SASEC = "378e52b0-c0a9-11cf-822d-00aa0051e40f";
  public static final String TASK_SCHEDULER = "86d35949-83c9-4044-b424-db363231fd0c";
  public static final String DRSUAPI = "e3514235-4b06-11d1-ab04-00c04fc2dcd2";
  public static final String WBEM_SERVICES = "9556dc99-828c-11cf-a37e-00aa003240c7";

  /** Interface UUID (lower case) → short name. */
  private static final Map<String, String> INTERFACES = Map.ofEntries(
      Map.entry(SVCCTL, "svcctl"),
      Map.entry(ATSVC, "atsvc"),
      Map.entry(SASEC, "sasec"),
      Map.entry(TASK_SCHEDULER, "ITaskSchedulerService"),
      Map.entry(DRSUAPI, "drsuapi"),
      Map.entry("12345778-1234-abcd-ef00-0123456789ac", "samr"),
      Map.entry("12345778-1234-abcd-ef00-0123456789ab", "lsarpc"),
      Map.entry("c681d488-d850-11d0-8c52-00c04fd90f7e", "efsrpc"),
      Map.entry("df1941c5-fe89-4e79-bf10-463657acf44d", "efsrpc"),
      Map.entry("338cd001-2244-31f1-aaaa-900038001003", "winreg"),
      Map.entry("4b324fc8-1670-01d3-1278-5a47bf6ee188", "srvsvc"),
      Map.entry("6bffd098-a112-3610-9833-46c3f87e345a", "wkssvc"),
      Map.entry("12345678-1234-abcd-ef00-01234567cffb", "netlogon"),
      Map.entry("12345678-1234-abcd-ef00-0123456789ab", "spoolss"),
      Map.entry("e1af8308-5d1f-11c9-91a4-08002b14a0fa", "epm"),
      Map.entry("99fcfec4-5260-101b-bbcb-00aa0021347a", "IObjectExporter"),
      Map.entry("000001a0-0000-0000-c000-000000000046", "IRemoteSCMActivator"),
      Map.entry("4d9f4ab8-7d1c-11cf-861e-0020af6e7c57", "IActivation"),
      Map.entry("00000143-0000-0000-c000-000000000046", "IRemUnknown2"),
      Map.entry("f309ad18-d86a-11d0-a075-00c04fb68820", "IWbemLevel1Login"),
      Map.entry(WBEM_SERVICES, "IWbemServices"),
      Map.entry("d4781cd6-e5d3-44df-ad94-930efe48a887", "IWbemLoginClientID"),
      Map.entry("82273fdc-e32a-18c3-3f78-827929dc23ea", "eventlog"),
      Map.entry("f6beaff7-1e19-4fbb-9f8f-b89e2018337c", "eventlog6"),
      Map.entry("3919286a-b10c-11d0-9ba8-00c04fd92ef5", "dssetup"),
      Map.entry("894de0c0-0d55-11d3-a322-00c04fa321a1", "InitShutdown"),
      Map.entry("d95afe70-a6d5-4259-822e-2c84da1ddb0d", "WindowsShutdown"));

  /** "interface/opnum" → operation name. */
  private static final Map<String, String> OPERATIONS = Map.ofEntries(
      Map.entry(SVCCTL + "/1", "ControlService"),
      Map.entry(SVCCTL + "/2", "DeleteService"),
      Map.entry(SVCCTL + "/11", "ChangeServiceConfigW"),
      Map.entry(SVCCTL + "/12", "CreateServiceW"),
      Map.entry(SVCCTL + "/15", "OpenSCManagerW"),
      Map.entry(SVCCTL + "/16", "OpenServiceW"),
      Map.entry(SVCCTL + "/19", "StartServiceW"),
      Map.entry(SVCCTL + "/23", "ChangeServiceConfigA"),
      Map.entry(SVCCTL + "/24", "CreateServiceA"),
      Map.entry(SVCCTL + "/27", "OpenSCManagerA"),
      Map.entry(SVCCTL + "/28", "OpenServiceA"),
      Map.entry(SVCCTL + "/31", "StartServiceA"),
      Map.entry(SVCCTL + "/44", "CreateServiceWOW64A"),
      Map.entry(SVCCTL + "/45", "CreateServiceWOW64W"),
      Map.entry(ATSVC + "/0", "NetrJobAdd"),
      Map.entry(SASEC + "/0", "SASetAccountInformation"),
      Map.entry(TASK_SCHEDULER + "/1", "SchRpcRegisterTask"),
      Map.entry(TASK_SCHEDULER + "/12", "SchRpcRun"),
      Map.entry(DRSUAPI + "/0", "DRSBind"),
      Map.entry(DRSUAPI + "/3", "DRSGetNCChanges"),
      Map.entry(DRSUAPI + "/17", "DRSAddEntry"),
      Map.entry(WBEM_SERVICES + "/24", "ExecMethod"),
      Map.entry(WBEM_SERVICES + "/25", "ExecMethodAsync"),
      Map.entry("12345678-1234-abcd-ef00-01234567cffb/4", "NetrServerReqChallenge"),
      Map.entry("12345678-1234-abcd-ef00-01234567cffb/26", "NetrServerAuthenticate3"),
      Map.entry("12345678-1234-abcd-ef00-01234567cffb/30", "NetrServerPasswordSet2"),
      Map.entry("4b324fc8-1670-01d3-1278-5a47bf6ee188/15", "NetrShareEnum"),
      Map.entry("12345778-1234-abcd-ef00-0123456789ac/17", "SamrLookupNamesInDomain"),
      Map.entry("12345678-1234-abcd-ef00-0123456789ab/65", "RpcRemoteFindFirstPrinterChangeNotificationEx"));

  /** The interface's short name, or null for one not in the table. */
  public static String interfaceName(String uuid) {
    return uuid == null ? null : INTERFACES.get(uuid.toLowerCase(Locale.ROOT));
  }

  /** The operation's name, or null when it isn't one of the named ones. */
  public static String operationName(String uuid, Integer opnum) {
    if (uuid == null || opnum == null) return null;
    return OPERATIONS.get(uuid.toLowerCase(Locale.ROOT) + "/" + opnum);
  }
}
