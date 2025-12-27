#import <UIKit/UIKit.h>

@interface ISMainViewController : UIViewController

@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) UISearchBar *searchBar;
@property (nonatomic, strong) NSArray *apps;
@property (nonatomic, strong) NSArray *filteredApps;
@property (nonatomic, strong) UIRefreshControl *refreshControl;
@property (nonatomic, strong) UIActivityIndicatorView *loadingIndicator;
@property (nonatomic, strong) UILabel *emptyLabel;
@property (nonatomic, strong) UIView *blurOverlay;
@property (nonatomic, assign) BOOL showApps;
@property (nonatomic, strong) NSMutableArray *favorites;

- (void)importFromFiles;
- (void)webDAVTransfer;
- (void)qrCodeImport;
- (void)showGameSaveOptions:(id)save;

@end
