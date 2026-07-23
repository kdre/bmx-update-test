#ifndef BMX_UPDATE_UPDATE_SERVICE_H
#define BMX_UPDATE_UPDATE_SERVICE_H

namespace bmx {
namespace update {

// These functions are reachable only through the explicit BMX Update menu
// action. No constructor, boot hook, timer or network callback invokes online
// discovery.
int CheckForUpdateFromMenu(char *message, unsigned message_size);
int PreparedDraftTestAvailableForMenu();
int BeginPreparedDraftTestFromMenu(char *message, unsigned message_size);
int CompletePreparedDraftTestFromMenu(char *message, unsigned message_size);
void CancelPendingUpdateFromMenu();
int InstallCheckedUpdateFromMenu(bool destructive_reset_consent,
                                 char *message, unsigned message_size);
bool ReadInstalledVersionForMenu(char *version, unsigned version_size);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_SERVICE_H
